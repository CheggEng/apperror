from apperror import AppLogger, AppStatus, AppError
import six # so this module can work with both python 2 and 3 (2*3 = 6)
import io # for buffering
import re # for testing
#
# These are libraries that help implement the principles of effective logging.
#
# AppLogger logs messages to include
#  * The name of the system generating the message (helpful in pipelines)
#  * The file name and line number where the log is written (helpful for quickly finding the relevant code)
#  * The log level of the message (useful for quick identification and filtering)
#  * The actual message
#  AppLogger allows you to specify the actual message as a list instead of a string, which makes it efficient enough
#   that you typically don't have to check the log level, and you can just call the log function blindly.  Example:
#  l = AppLogger('demo')
#  l.debug("This call won't build a big string from my list of numbers, ", [0, 1, 2, 3], " or serialize ",
#          my_complex_object, " unless debugging is turned on, so I can feel free to make lots of logging statements!")
#  if l.isSetDebug():
#      l.debug("I do want to protect logging inside conditional if I need to log with ", slow_function_call())
#
# AppStatus is like AppLogger, except it is a container for storing these various diagnostics, so they can be logged or
#   variously handled at higher levels in the call stack, providing for the principles of "effective logging".
#   It also provides a mechanism for passing computed values up the call stack, either individually, or multiple values
#   at once.  Think of it as a ledger to keep track of the things that happened so far in your program.
#   You don't have to make the hard choice of should I return a value, or should I throw an exception to indicate a 
#   special condition.  You can report everything and let the caller decide, but if they forget to explicitly ignore
#   errors, we'll still throw an exception.
#
# AppError is the same as AppStatus, but turned into an exception for those times when you really do want to throw an
#   exception.  But, included with the exception you can still have your ledger of computed value(s) and other 
#   diagnostics you collected up to the failure point, like warnings and info messages.
#   AppError doesn't inherit from AppStatus because AppStatus doesn't collect a stack trace, but AppError does.

# Basic usage - logger

l = AppLogger('demo')

def do_basic_logging(l):
    ''' Illustrates using the logger '''
    l.error("I owe: $", 300 + 100, " dollars to my ex")
    l.warn("I don't have enough money in the bank:  $", 0)
    l.info("wise to pay your debts!")
    l.debug("i probably shouldn't have borrowed gas money from her")
    l.verbose = 2
    l.v1("I borrowed $400")
    l.v2("First it was $300")
    l.v2("Then it was another $100")
    l.v3("(It was to pay the rent)")
    return '''
demo: ERROR: demo.py:38: I owe: $400 dollars to my ex
demo: WARN: demo.py:39: I don't have enough money in the bank:  $0
demo: INFO: demo.py:40: wise to pay your debts!
demo: DEBUG: demo.py:41: i probably shouldn't have borrowed gas money from her
demo: V1: demo.py:43: I borrowed $400
demo: V2: demo.py:44: First it was $300
demo: V2: demo.py:45: Then it was another $100
'''

# Basic usage - status

def do_basic_status(l):
    ''' Illustrates using the AppStatus object '''
    s = AppStatus()
    if s.ok: l.info("we're doing fine")
    
    s = AppStatus("unable to find boot sector")
    s.addWarn("backup all data now")
    print(six.text_type(s))
    if s.hasErrors(): l.error("We have a problem: ", six.text_type(s))  # shows whole status, inc. the warning
    return '''
demo: INFO: demo.py:57: we're doing fine
demo: ERROR: demo.py:61: We have a problem: demo.py:59: unable to find boot sector; WARNINGS: demo.py:60: backup all data now
'''

## usage of verbose

def showVerbosity(l):
    ''' Illustrates using verbosity levels '''
    l.ifverbose("ok, we're verbose!")
    l.ifverbose(2, "very verbose!")
    if l.verbose > 2:
        l.warn("we're too darned verbose!")

def do_show_verbose(l):
    l1 = AppLogger('demo', verbose=2)  # can set in the constructor
    l1.diag_stream = l.diag_stream
    showVerbosity(l1)
    l1.v1("a verbose message")         # alternate syntax for creating log messages at different levels of verbosity
    l1.v2("a very verbose message")
    l1.v3("a very, very verbose message")
    l1.verbose = 1                     # property way to set
    showVerbosity(l1)
    l1.setVerbose(0)                   # equivalent way to set
    showVerbosity(l1)
    return '''
demo: V1: demo.py:75: ok, we're verbose!
demo: V2: demo.py:76: very verbose!
demo: V1: demo.py:83: a verbose message
demo: V2: demo.py:84: a very verbose message
demo: V1: demo.py:75: ok, we're verbose!
'''

## usage of debug

def do_show_debug(l):
        
    def showDebugLevel(l):
        l.ifdebug("we're debuggin!")
        l.ifdebug(5, " =? ", 2 + 3, tag="math")
        l.ifdebug("spelling is a breeze", tag='spelling')
    
    l1 = AppLogger('demo', debug=True)  # can set in the constructor
    l1.diag_stream = l.diag_stream
    showDebugLevel(l1)
    l.setDebug(False)                  # equivalent way to set
    showDebugLevel(l)
    l.setDebug('math')                 # can set to debug by tagname
    showDebugLevel(l)
    l.setDebug(['math', 'art'])        # or multiple tags
    showDebugLevel(l)
    return '''
demo: DEBUG: demo.py:103: we're debuggin!
demo: INFO: demo.py:111: math debugging enabled
demo: DEBUG[math]: demo.py:103: 5 =? 5
demo: INFO: demo.py:113: math debugging enabled
demo: INFO: demo.py:113: art debugging enabled
demo: DEBUG[math]: demo.py:103: 5 =? 5
'''

## getting log string instead of actually logging
def do_log_to_string(l):
    ''' Illustrates logging to a string instead of to the current diagnostics stream, e.g. stderr '''
    for_later = l.info("I want to capture this log message for later", as_string=True)
    l.info("Earlier I saw this message: ", for_later)
    return '''
demo: INFO: demo.py:134: Earlier I saw this message: demo: INFO: demo.py:133: I want to capture this log message for later
'''

## write a diagnostic at INFO level showing how the program has been called
## I like to put this at the start of every program, so I can easily tell what log level the program ran at
def do_announce_myself(l):
    l.announceMyself()  # can also be called with as_string=True parameter if you don't want to log immediately
    return '''
demo: INFO: demo.py:141: called as: pytest demo.py
'''

# More fun with status object

## direct testing
def do_app_status_as_bool(l):
    s = AppStatus()
    if s: # same as if s.ok
        l.info("we're ok")
    return '''
demo: INFO: demo.py:152: we're ok
'''

## dumping the status object
### shows all info, warnings, errors, and everything else in the status object, s
def do_app_status_dump(l):
    l.info(six.text_type(AppStatus()))
    return '''
demo: INFO: demo.py:160: ok
'''

## adding/removing info/warnings/errors to the status
def do_add_diagnostics_to_status(l):
    s = AppStatus()
    s.addInfo("threshold 1 was not met")
    s.addInfo("threshold 2 was not met")
    if s.hasInfo():
        l.info(s.getInfo())
        s.clearInfo()              # way to clear diagnostics 
    s.addWarn("I think the wheels fell off")
    if s.hasWarnings():
        l.warn(s.warnMsg())
        for warn in s.warnings:    # it's a list we can iterate
            if "the wheels fell off" in warn:
                s.addError(warn)   # will record this line number and line number of warning
        s.warnings = []            # We can also assign directly to the list, e.g. to clear
    if s.hasErrors():
        l.error(s.errorMsg())      # N.B. l.error(s) would be the same
    return '''
demo: INFO: demo.py:171: demo: INFO: demo.py:168: threshold 1 was not met; demo: INFO: demo.py:169: threshold 2 was not met
demo: WARN: demo.py:175: demo: WARN: demo.py:173: I think the wheels fell off
demo: ERROR: demo.py:181: demo: ERROR: demo.py:178: demo: WARN: demo.py:173 I think the wheels fell off
'''
    
## adding a return value to status object (e.g. to pass it up the call stack along with the diagnostics)
def do_add_value_to_status(l):
    s = AppStatus("Houston, we have a problem")
    s.addValue("foo")
    try:
        l.info("got value '", s.getValue(), "'")
    except AppError as err:
        l.warn(str(err))
        s.clearErrors()
        l.info("got value '", s.getValue(), "'")  # now, no problem
    return '''
demo: WARN: demo.py:195: demo.py:193: You must clear errors on status object before accessing value: demo.py:190: Houston, we have a problem
demo: INFO: demo.py:197: got value 'foo'
'''

## adding additional values to the status object
def do_add_additional_values_to_status(l):
    s = AppStatus()
    s.my_other_value = "bar"   # I can use any property name here
    s.my_last_value = "last"
    l.info("my status also has value ", s.my_other_value)
    
    ### getExtraAttrs() returns a dictionary with all the custom values as kv pairs (does not include s.getValue())
    l.info("custom value: ", s.getExtraAttrs()["my_other_value"])
    return '''
demo: INFO: demo.py:207: my status also has value bar
demo: INFO: demo.py:210: custom value: bar
'''

def do_dedup_messages(l):
    s = AppStatus()
    # deduping messages to remove clutter
    for _ in range(2):
        s.addInfo("threshold 1 was not met")
    s.dedupInfo()  # two messages about threshold 1 on same line become a single message with (x2) indicator
    l.info(s.infoMsg())
    return '''
demo: INFO: demo.py:222: demo.py:220: threshold 1 was not met (x2)
'''

## the "last_error"
def do_check_last_error(l):
    ### this is the last error added to the status
    s = AppStatus("1. bad stuff happened")  # last_error = "1. bad stuff ..."
    s.addError("2. the driver bailed")      # last_error  = "2. the driver ..."
    current_status = AppStatus("3. the wheels fell off the bus")
    s.addStatus(current_status)             # last_error = "3. the wheels ..."
    if "the wheels fell off" in s.last_error:
        l.info("at the end of the day, the wheels fell off")
    else:
        l.error("unexpected sequence of events; last error was: ", s.last_error)
    return '''
demo: INFO: demo.py:236: at the end of the day, the wheels fell off
'''

## converting between status object and exception
def do_switch_between_status_and_exception(l):
    s = AppStatus("the wheels fell off the bus")
    try:
        # We can turn the status object to an AppError exception
        raise AppError(str(s))
        # Or we can directly create the AppError as easily as an AppStatus object
        raise AppError("Unexpectedly, we still have ", 4, " wheels")
    except AppError as err:
        # we turn the exception back to a status object, e.g. to combine it with other status objects, etc.
        current_status = err.to_status()
        current_status.addWarn("Now we can do more with the status object")
        l.info(str(current_status))
    return '''
demo: INFO: demo.py:255: demo.py:248: demo.py:245: the wheels fell off the bus; WARNINGS: demo.py:254: Now we can do more with the status object
'''

## merging status objects together
### Handy to keep track of the cumulative outcome of multiple function calls
def get_merged_status_objects():
    ''' returns a status object that is result of merging two together '''
    s1 = AppStatus().addInfo("Stuff is going well").addValue(1)
    s2 = AppStatus("This time we blew it").addValue(2)
    s2.foo = 'bar'  # extra attribute
    ### here we'll combine the info, error, and custom values set on both status objects, but when there are
    ###   conflicts, the last status object wins, so value will be 2
    s1.addStatus(s2)
    return s1

def do_merge_status_objects(l):
    s1 = get_merged_status_objects()
    l.info(str(s1))
    return '''
demo: INFO: demo.py:196: demo.py:191: This time we blew it; INFO: demo.py:190: Stuff is going well; extra attributes: {'value': 2, 'foo': 'bar'}
'''

## Logging all status levels at the appropriate log level
### The logger will create an INFO for each info entry in the status object, a WARN entry for each warn
###  etnry, etc.
def do_log_all_levels(l):
    s1 = get_merged_status_objects()
    s1.log(l)
    ### we can also prepend a custom message to each of those log lines
    s1.log(l, "This is how it went down")
    return '''
demo: ERROR: demo.py:284: demo.py:191: This time we blew it
demo: INFO: demo.py:284: demo.py:190: Stuff is going well
demo: ERROR: demo.py:286: This is how it went down: demo.py:191: This time we blew it
demo: INFO: demo.py:286: This is how it went down: demo.py:190: Stuff is going well
'''
    
# Advanced usage

## capture all log messages into a buffer
def do_capture_into_a_buffer(l):
    buff = io.StringIO()
    restore = l.diag_stream
    l.diag_stream = buff
    l.info("logging to a string now")
    l.diag_stream = restore
    l.info("logging normally again; earlier we got: " + buff.getvalue())
    buff.close()
    return '''
demo: INFO: demo.py:305: logging normally again; earlier we got: demo: INFO: demo.py:301: logging to a string now
'''

## easily set log levels from your commandline arguments
##   -- only works if you're using a "standard" commandline parser like docopt and you define 'debug' or 'verbose'
##   arguments, which will set 'debug'/'verbose' properties in your object or keys in a dict
def do_set_from_args(l):
    from docopt import docopt
    usage = '''
Usage: 
  demo [--verbose]... [--debug]
'''
    args = docopt(usage, argv=['--verbose', '--verbose'], version='demo 1.0')
    l.setFromArgs(args)
    showVerbosity(l)  # will show how verbose we are, depending on which arguments were passed to demo
    return '''
demo: V1: demo.py:78: ok, we're verbose!
demo: V2: demo.py:79: very verbose!
'''

## logging a line from higher in the call stack
### When you have an error handler you don't want to put the file location of the handler in the log.  
###  Instead, you want to log the location where the error was detected.  All of the logger functions have 
###  the ability to specify higher stack frames to use when constructing the log message.
###  See this example:
def do_hide_deep_call_stack(l):
    def constructStatus(msg):
        # We return the string, instead of logging immediately because of as_string parameter
        return l.error("I'm deep in the error handler: ", msg, extra_frames=2, as_string=True)
    def handleError(msg):
        # Maybe I want to send diagnostics somewhere other than the standard log file, or do other processing on errors,
        #  so I make an error handler
        deep_msg = constructStatus(msg)  # this is just for illustration
        # AppLogger functions accept the extra_frames parameter
        l.warn("I'm in the error handler: ", deep_msg, extra_frames=1)
    handleError("Root problem is here")
    return '''
demo: WARN: demo.py:341: I'm in the error handler: demo: ERROR: demo.py:341: I'm deep in the error handler: Root problem is here
'''

## usage of numFramesInThisModule tells you how deep you are into the callstack for the current module
### frame 1: top level
### frame 2: test_do_tell_me_how_deep_i_am()
### frame 3: do_tell_me_how_deep_i_am(l)
### frame 4: c()
### frame 5: b()
### frame 6: a()
def do_tell_me_how_deep_i_am(l):
    from apperror import numFramesInThisModule
    def a():
        l.info("num frames deep in this module: ", numFramesInThisModule())
    def b():
        a()
        l.info("num frames deep in this module: ", numFramesInThisModule())
    def c():
        b()
        l.info("num frames deep in this module: ", numFramesInThisModule())
    c()
    return '''
demo: INFO: demo.py:350: num frames deep in this module: 6
demo: INFO: demo.py:353: num frames deep in this module: 5
demo: INFO: demo.py:356: num frames deep in this module: 4
'''

# END OF TEST CASES

# Testing code utilies
norm_filepath = re.compile(r'\S*demo.py:\d+')
norm_pytest = re.compile(r'\S*pytest[3]?')

def assertMatching(a, b):
    ''' Asserts that the log lines from string, a, match the log lines in the string, b.
    a is the expected string / pattern
    b is the actual string
    We ignore leading/trailing whitespace, line-numbers, and the filepath before demo.py and pytest.
    '''
    a_lines = a.strip().split("\n")
    b_lines = b.strip().split("\n")
    if len(a_lines) != len(b_lines):
        raise AssertionError("a has " + six.text_type(len(a_lines)) + ", but b has " + six.text_type(len(b_lines)) + " lines: a={" + a + "}, b={" + b + "}")
    for i in range(0, len(a_lines)):
        a_line = norm_filepath.sub('demo.py:<LINE>', a_lines[i])
        a_line = norm_pytest.sub('pytest', a_line)
        b_line = norm_filepath.sub('demo.py:<LINE>', b_lines[i])
        b_line = norm_pytest.sub('pytest', b_line)
        assert a_line == b_line
        
def assert_log_output_is_as_expected(func):
    '''Validates that the given logging function produces the expected result'''
    # First buffer the results
    buff = io.StringIO()
    restore = l.diag_stream
    l.diag_stream = buff
    # make the call
    sample_output = func(l)
    # check the result
    try:
        assertMatching(sample_output, buff.getvalue())
    finally:
        # free the buffer / restore logger to normal
        l.diag_stream = restore
        buff.close()

def test_basic_logging():
    assert_log_output_is_as_expected(do_basic_logging)
    
def test_basic_status():
    assert_log_output_is_as_expected(do_basic_status)
    
def test_show_verbose():
    assert_log_output_is_as_expected(do_show_verbose)
    
def test_show_debug():
    assert_log_output_is_as_expected(do_show_debug)
    
def test_log_to_string():
    assert_log_output_is_as_expected(do_log_to_string)
    
def test_announce_myself():
    assert_log_output_is_as_expected(do_announce_myself)
    
def test_app_status_dump():
    assert_log_output_is_as_expected(do_app_status_dump)
    
def test_add_value_to_status():
    assert_log_output_is_as_expected(do_add_value_to_status)
    
def test_add_additional_values_to_status():
    assert_log_output_is_as_expected(do_add_additional_values_to_status)

def test_dedup_messages():
    assert_log_output_is_as_expected(do_dedup_messages)

def test_check_last_error():
    assert_log_output_is_as_expected(do_check_last_error)

def test_switch_between_status_and_exception():
    assert_log_output_is_as_expected(do_switch_between_status_and_exception)
    
def test_merge_status_objects():
    # attributes can be printed in any order from dictionary, so we need to normalize those before testing outputs
    ## create our own buffered logger, and get the relevant values
    buff = io.StringIO()
    l = AppLogger('demo')
    l.diag_stream = buff
    val_expected = do_merge_status_objects(l)
    val_actual = buff.getvalue()
    buff.close()
    ## now, pull out the attributes dictionaries and compare them seperately
    regex_pull_last_dict = re.compile(r'{.*}$')
    final_dict_expected = eval(regex_pull_last_dict.search(val_expected).group(0))
    final_dict_actual = eval(regex_pull_last_dict.search(val_actual).group(0))
    assert final_dict_expected == final_dict_actual
    ## pull those dictionaries off the strings, and make sure the rest of the strings match
    val_actual_trimmed = regex_pull_last_dict.sub('', val_actual)
    val_expected_trimmed = regex_pull_last_dict.sub('', val_expected)
    assertMatching(val_actual_trimmed, val_expected_trimmed)
    
def test_do_log_all_levels():
    assert_log_output_is_as_expected(do_log_all_levels)
    
def test_do_capture_into_a_buffer():
    assert_log_output_is_as_expected(do_capture_into_a_buffer)
    
def test_do_set_from_args():
    assert_log_output_is_as_expected(do_set_from_args)
    
def test_do_hide_deep_call_stack():
    assert_log_output_is_as_expected(do_hide_deep_call_stack)

def test_do_tell_me_how_deep_i_am():
    assert_log_output_is_as_expected(do_tell_me_how_deep_i_am)

if __name__ == "__main__":
    do_basic_logging(l)
    do_basic_status(l)
    do_show_verbose(l)
    do_show_debug(l)
    do_log_to_string(l)
    do_announce_myself(l)
    do_app_status_dump(l)
    do_add_value_to_status(l)
    do_add_additional_values_to_status(l)
    do_dedup_messages(l)
    do_check_last_error(l)
    do_switch_between_status_and_exception(l)
    do_merge_status_objects(l)
    do_log_all_levels(l)
    do_capture_into_a_buffer(l)
    do_set_from_args(l)
    do_hide_deep_call_stack(l)
    do_tell_me_how_deep_i_am(l)
