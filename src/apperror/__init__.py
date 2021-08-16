#!/usr/bin/env python

'''
This module provides classes to make reporting of errors easier, more informative, and more standard.

See examples in demo.py for usage.

Please see the README.md for more information.

Copyright (c) 2017 Joshua Richardson, Chegg Inc.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import sys, inspect, traceback, collections
# dumper helps print out any data structure into readable form
from dumper import dumps

import os
import copy

'This description documents many of the logging functions later in this module.'
LOG_FUNC_DESCRIPTION = '''
kwargs can contain these keys:
 * extra_frames:  a positive integer indicating how many stack frames to
     go up before reporting the code location of this diagnostic [default: 0]
 * as_string:  set True if you want a string back instead of printing to
    self.diag_stream
'''    

def numFramesInThisModule():
    '''
Return the number of contiguous stack frames that are in the module where this
  function is called, including and starting from the frame of the function
  call.  If all the frames are in that same module, we return the number of
  such frames minus 1, so code can report relative to the top frame.
'''
    frames = traceback.extract_stack()
    if len(frames) < 2: return 0
    this_module = frames[-2][0]
    for i in range(len(frames) - 2):
        if frames[-3 - i][0] != this_module: return i + 1
    return len(frames) - 1

def adorn(msg, *more_msg, **kwargs):
    ''' Add file and lineno info to msg.

        kwargs can contain:
          extra_frames:  how many extra frames to go up, when capturing lineno
'''
    extra_frames = kwargs['extra_frames'] if 'extra_frames' in kwargs else 0
    calling_frame = inspect.currentframe().f_back
    for _ in range(extra_frames):
        calling_frame = calling_frame.f_back
    line_no = str(calling_frame.f_lineno)
    call_file = inspect.getsourcefile(calling_frame)
    def makeASCII(s):
        if isinstance(s, str):
            return s.encode('ascii', errors='replace').decode()
        elif isinstance(s, (int, float, complex)):
            return str(s)
        elif isinstance(s, Exception):
            return traceback.format_exc()
        else:
            return dumps(s)

    pmsg = [makeASCII(m) for m in (msg,) + more_msg]
    try:
        return call_file + ":" + line_no + ": " + ''.join(pmsg)
    except UnicodeEncodeError as ex:
        raise Exception("Unable to use message of type " + \
                        str(type(pmsg)) + ": " + str(ex))

class AppLogger(object):
    ''' Encapsulates some convenience functions for error-logging '''
    
    def __init__(self, component_name, verbose=None, debug=False):
        '''
        component_name: prepended to all logs from this logger, so you know what system generated the noise
        verbose:  a number, 0+ which turns on extra logging
        debug:  Higher log level than verbose, or set to a string or list of strings to turn on named
           diagnostic streams.
        '''
        if not isinstance(component_name, str):
            raise ValueError("component_name must be a string")
        self.component = component_name
        self.debug_tags = {} # tag -> None, for each tag
        if isinstance(debug, bool):
            if debug:
                self.debug_tags['*'] = None
        # diagnostic stream -- where to write messages
        self.diag_stream = sys.stderr
        # need something with acquire() and release() to keep output from
        #  garbling; doesn't work on CentOS 5
        self.lock = None
        if verbose is not None:
            self.verbose = verbose

        global LOG_FUNC_DESCRIPTION
        self.LOG_FUNC_DESCRIPTION = LOG_FUNC_DESCRIPTION
    
    @property
    def verbose(self):
        if not hasattr(self, '_verbose'):
            raise EnvironmentError("verbose was not specified for this logger")
        return self._verbose
    
    @verbose.setter
    def verbose(self, val):
        self._verbose = val
#         if val:
#             self.info("verbose: " + str(val),
#                       extra_frames=numFramesInThisModule())
            
    def setVerbose(self, val):
        ''' for folks who prefer the Java bean style setter '''
        self.verbose = val
            
    def setDebug(self, tags_or_bool=True):
        '''
        tags_or_bool:
            True / False: turns on / off debugging globally
            String / List of strings: turns on debugging for the given diagnostic stream / list of streams
'''
        if tags_or_bool == True:
            tags_or_bool = ['*']
        elif tags_or_bool == False:
            self.debug_tags.clear()
            tags_or_bool = []
        elif isinstance(tags_or_bool, str):
            tags_or_bool = [tags_or_bool]
        try:
            for tag in tags_or_bool:
                self.debug_tags[tag] = None
                self.info(tag + " debugging enabled",
                          extra_frames=numFramesInThisModule())
        except TypeError:
            raise TypeError("Invalid type of argument for setDebug(): ",
                            str(type(tags_or_bool)))
    
    def isSetDebug(self, tag=None):
        if tag is not None:
            return tag in self.debug_tags
        return len(self.debug_tags) > 0

    def setFromArgs(self, args):
        '''
Set the verbose and debug levels from an object which should either be
 * a dictionary with keys '--verbose' and '--debug'
 * an object with attributes 'verbose' and 'debug'
 Debug can be a comma-seperated list of channel names to enable debugging for.
'''
        
        debug = None
        try:
            verbose = args.verbose
            try:
                verbose = len(verbose)
            except TypeError:
                try:
                    verbose = int(verbose)
                except TypeError:
                    verbose = None
            try:
                debug = args.debug
            except AttributeError:
                pass
        except (TypeError, AttributeError) as err:
            self.ifdebug(err)
            verbose = args['--verbose']
            try:
                debug = args['--debug']
            except:
                pass
        
        if verbose:
            self.verbose = verbose
        else:
            self.verbose = 0
        
        debug_tags = []

        try:
            debug_iter = iter(debug)
            for tag in debug_iter:
                debug_tags.extend(tag.split(','))
        except TypeError:
            pass

        self.setDebug(debug_tags)
    
    def ifdebug(self, msg, *more_msg, **kwargs):
        '''
    Can be called like
        ifdebug(msg) or
        ifdebug(msg, tag=foo)
        ''' + self.LOG_FUNC_DESCRIPTION + '''
    If tag is set as a parameter, then we write a debug message only if that tag is currently enabled.
        '''
        if not 'tag' in kwargs:
            tag = '*'
        else:
            tag = kwargs['tag']
            if not isinstance(tag, str):
                raise AppError("Tag must be a string, but is ", type(tag), "; tag: ", tag)
#         
#         if not isinstance(msg, str):
#             raise AppError("Msg must be a string, but is ", type(msg), "; msg: ", msg)
        if tag in self.debug_tags:
            kwargs['extra_frames'] = 1
            self.debug(msg, *more_msg, **kwargs)
        
    def v1(self, msg, *more_msg, **kwargs):
        self.LOG_FUNC_DESCRIPTION
        if self.verbose:
            return self.commonOut('V1', msg, *more_msg, **kwargs)
        return ''
    
    def v2(self, msg, *more_msg, **kwargs):
        self.LOG_FUNC_DESCRIPTION
        if self.verbose >= 2:
            return self.commonOut('V2', msg, *more_msg, **kwargs)
        return ''
    
    def v3(self, msg, *more_msg, **kwargs):
        self.LOG_FUNC_DESCRIPTION
        if self.verbose >= 3:
            return self.commonOut('V3', msg, *more_msg, **kwargs)
        return ''
    
    def ifverbose(self, lvl_or_msg, msg=None):
        '''
Only log if verbose, or if verbosity higher than given verbosity.
    lvl_or_msg:  verbosity level of message, unless it's the only arg, in which case it's the message to log.
    msg:  the message to log.
'''
        if msg is None:
            lvl = 1
            msg = lvl_or_msg
        else:
            lvl = lvl_or_msg
        if lvl <= self.verbose:
            self.commonOut('V' + str(lvl), msg)
    
    def debug(self, msg, *more_msg, **kwargs):
        '''
    This function always writes a message prepended by DEBUG (use ifdebug() for conditional logging)
    tag: if set, indicates which tag was used to enable this debug message''' + \
        self.LOG_FUNC_DESCRIPTION
        try:
            tag = kwargs['tag']
        except KeyError:
            tag = '*'
        tag_adorn = ''.join(['[', tag, ']']) if tag != '*' else ''
        return self.commonOut('DEBUG' + tag_adorn, msg, *more_msg, **kwargs)
        
    def info(self, msg, *more_msg, **kwargs):
        self.LOG_FUNC_DESCRIPTION
        return self.commonOut('INFO', msg, *more_msg, **kwargs)

    def warn(self, msg, *more_msg, **kwargs):
        self.LOG_FUNC_DESCRIPTION
        return self.commonOut('WARN', msg, *more_msg, **kwargs)

    def err(self, msg, *more_msg, **kwargs):
        self.LOG_FUNC_DESCRIPTION
        return self.commonOut('ERROR', msg, *more_msg, **kwargs)
    def error(self, msg, *more_msg, **kwargs):
        '''
        Alias for the 'err' function.  Writes message at error log level.
''' + \
        self.LOG_FUNC_DESCRIPTION
        return self.commonOut('ERROR', msg, *more_msg, **kwargs)

    def commonOut(self, lvl, msg, *more_msg, **kwargs):
        '''
        Write the given message at the given log level.
''' + \
        self.LOG_FUNC_DESCRIPTION
        extra_frames = \
            (kwargs['extra_frames'] if 'extra_frames' in kwargs else 0) + \
            2  # get above commonOut() and error()/warn()/info()/etc.
        as_string = kwargs['as_string'] if 'as_string' in kwargs else False
        formatted = self.component + ": " + lvl + ": " + \
            adorn(msg, *more_msg, extra_frames=extra_frames)
        if as_string:
            return formatted
        else:
            if self.lock is not None:
                self.lock.acquire()
            print(formatted, file=self.diag_stream)
            if self.lock is not None:
                self.lock.release()

    def announceMyself(self, as_string=False):
        '''
        Writes diagnostic indicating arguments used to execute current program.
        
        as_string, if True return string instead.
'''
        return self.info("called as: " + ' '.join(sys.argv),
                         extra_frames=1, as_string=as_string)

class AppStatus(object):
    '''
    Instead of using a logger, which has to write to a stream, you can pass this AppStatus object up and
      down your call stack and deal with the errors, warnings, etc. at a point of your application's
      choosing.
    Functions that return values, also store those values into this object.
    @param kwargs is for options; right now, only this one is supported:
      extra_frames - an integer number of stack frames that should be skipped when logging the location of a
        diagnostic message
'''
    
    def __init__(self, msg=None, *more_msg, **kwargs):
        '''
    If a message is supplied here, it is assumed that this status represents an error.
'''
        # The following is to provide common description for member functions that do logging
        global LOG_FUNC_DESCRIPTION
        self.LOG_FUNC_DESCRIPTION = LOG_FUNC_DESCRIPTION

        self._info = []
        self.warnings = []
        self.errors = []
        self.last_error = ''
        if not msg is None:
            self.addError(msg, *more_msg, **kwargs)
        self.value = None
    
    def __nonzero__(self):
        '''
    Provides for boolean testing of this status object:
      False:  There was an error.
      True:  There were NO errors.
'''
        return not self.hasErrors()
    
    # when making status into a string, show errors first, if any, then
    #  warnings, if any, then info, if any
    def __str__(self):
        '''
    Provides for printable view of this status object.
    
    Shows errors first, if any, then warnings, if any, then info, if any.
    
    If custom attributes have been set on the object, then those are displayed at the end.
'''
        buff = ''
        if self.hasErrors():
            buff += self.errorMsg()
        if len(self.warnings):
            if len(buff):
                buff += "; "
            buff += "WARNINGS: "
            buff += self.warnMsg()
        if len(self._info):
            if len(buff):
                buff += "; "
            buff += "INFO: "
            buff += self.infoMsg()
        if not len(buff):
            buff = 'ok'
        
        xtra_attrs = self._xtra_attrs_to_str()
        if len(xtra_attrs):
            buff += '; '
            buff += xtra_attrs  
        
        return buff
    
    def _xtra_attrs_to_str(self):
        extra_attrs = self.getExtraAttrs()

        return "extra attributes: " + str(extra_attrs) if len(self.getExtraAttrs().keys()) else '';
    
    _DEDUP_MSG = '''
    Identifies duplicate messages and dedups them but appends the count, e.g.
       No such key found 'foo' (x14)
    '''
    
    def _dedup(self, msgs):
        self._DEDUP_MSG
        counts = collections.OrderedDict()
        for i in msgs:
            counts[i] = 1 if i not in counts else counts[i] + 1
        del msgs[:]
        for (key, val) in counts.items():
            if val > 1:
                msgs.append(key + " (x" + str(val) + ')')
            else:
                msgs.append(key)
    
    def _getAdornedMsg(self, msg, *more_msg, **kwargs):
        ''' Creates the adorned message (adding line number, filename, etc.) and returns it '''
        extra_frames=numFramesInThisModule()
        try:
            extra_frames += int(kwargs['extra_frames'])
        except:
            pass  # user does not always specify extra_frames
        return adorn(msg, *more_msg, extra_frames=extra_frames)
    
    def addInfo(self, msg, *more_msg, **kwargs):
        self.LOG_FUNC_DESCRIPTION
        adorned_msg = self._getAdornedMsg(msg, *more_msg, **kwargs)
        self._info.append(adorned_msg)
        return self

    def addWarning(self, msg, *more_msg, **kwargs):
        self.LOG_FUNC_DESCRIPTION
        adorned_msg = self._getAdornedMsg(msg, *more_msg, **kwargs)
        self.warnings.append(adorned_msg)
        return self
    
    def addWarn(self, msg, *more_msg, **kwargs):
        self.LOG_FUNC_DESCRIPTION
        return self.addWarning(msg, *more_msg, **kwargs)

    def addError(self, msg, *more_msg, **kwargs):
        self.LOG_FUNC_DESCRIPTION
        adorned_msg = self._getAdornedMsg(msg, *more_msg, **kwargs)
        self.errors.append(adorned_msg)
        self.last_error = adorned_msg
        return self
    
    def addStatus(self, other):
        '''
    Combines the diagnostics from another status object to this object.
        '''
        if not isinstance(other, AppStatus):
            raise TypeError("addStatus() is for merging in another AppStatus object")
        self.errors.extend(other.errors)
        if other.last_error:
            self.last_error = other.last_error
        self.warnings.extend(other.warnings)
        self._info.extend(other._info)
        if other.value is not None:
            self.value = other.value
        for key, val in other.getExtraAttrs().items():
            self.__dict__[key] = val
        
        return self
        
    def addValue(self, val):
        '''
    Sets a return value on the status object.
        '''
        self.value = val
        
        return self
    
    @property
    def ok(self):
        '''
    Status is assumed to be ok if it has no errors.
        '''
        return not self.hasErrors()
    
    @property
    def warn(self):
        '''
    Status is in warn state if it has any warnings attached to it.
        '''
        return self.hasWarnings()
    
    def hasErrors(self):
        return len(self.errors) > 0
    
    def clearErrors(self):
        self.errors = []
    
    def hasWarnings(self):
        return len(self.warnings) > 0
    
    def clearWarnings(self):
        self.warnings = []
    
    def hasInfo(self):
        return len(self._info) > 0
    
    def clearInfo(self):
        self._info = []
    
    def dedupInfo(self):
        self._DEDUP_MSG
        self._dedup(self._info)
    
    def log(self, logger, msg=None):
        ''' spit out any diagnostics to the logger at the corresponding log levels '''
        prepend = ''
        if msg:
            prepend = msg + ': '
        if self.hasErrors():
            logger.error(prepend, self.errMsg(), extra_frames=1)
        if self.hasWarnings():
            logger.warn(prepend, self.warnMsg(), extra_frames=1)
        if self.hasInfo():
            logger.info(prepend, self.infoMsg(), extra_frames=1)
    
    def infoMsg(self):
        return '; '.join(self._info)
    
    def warnMsg(self):
        return '; '.join(self.warnings)

    def errorMsg(self):
        return '; '.join(self.errors)
    
    def errMsg(self):
        return self.errorMsg()
    
    def getInfo(self):
        return self._info
    
    def getValue(self):
        pass # redefined below after AppError declared
    
    def getExtraAttrs(self):
        xtra_attrs = copy.copy(self.__dict__)
        xtra_attrs_keys = []
        for key in xtra_attrs.keys():
            xtra_attrs_keys.append(key)
        for key in xtra_attrs_keys:
            if not len(key) or key[0] == '_':
                del xtra_attrs[key]
            elif key in ('_info', 'warnings', 'errors', 'last_error', 'LOG_FUNC_DESCRIPTION'):
                del xtra_attrs[key]
            elif key == 'value':
                if xtra_attrs[key] is None:
                    del xtra_attrs[key]

        return xtra_attrs
    
class AppError(Exception):
    '''
    An exception object that is created just like an AppStatus object and can be used as such with the to_status() member.
    @see AppStatus for more information on parameters and behavior
    '''
    def __init__(self, msg, *more_msg, **kwargs):
        '''
        @see AppStatus init for more information on parameters and behavior
        '''
        self.status = AppStatus(msg, *more_msg, **kwargs)
        Exception.__init__(self, str(self.status))
        
    def to_status(self):
        return self.status

def _statusGetValue(self):
    if self.hasErrors():
        raise AppError("You must clear errors on status object before accessing value: ", self.errMsg())
    return self.value

AppStatus.getValue = _statusGetValue
    
def deeperFrame():
    s.info("called from deeper stack frame", extra_frames=1)
    s.info("called in parts ", "from deeper frame", extra_frames=1)

def main():
    global s
    s = AppLogger("AppError.py", verbose=1)
    s.info("here is some info")
    s.info("message", " passed in parts")
    deeperFrame()
    s.warn("here is a warning")
    s.err("here is an error")
    s.v1("here is a verbose message")
    s.v2("we shouldn't see this verbose message!")
    s.info("string I get back from info with 'as_string': ",
           s.info('hello', as_string=True))

if __name__ == "__main__":
    main()
