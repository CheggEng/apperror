app_error
=========

The purpose of this module is to make logging and reporting of errors easier, more informative, and more
consistent.

There is one library for python and one for javascript that is not as fully-featured yet.

`AppLogger` logs messages to include
* The name of the system generating the message (helpful in pipelines)
* The file name and line number where the log is written (helpful for quickly finding the relevant code)
* The log level of the message (useful for quick identification and filtering)
* The actual message

`AppLogger` allows you to specify the actual message as a list instead of a string, which makes it efficient enough
that you typically don't have to check the log level, and you can just call the log function blindly.  Py example:

        l = AppLogger('demo')
        l.debug("This call won't build a big string from my list of numbers, ", [0, 1, 2, 3], " or serialize ",
                my_complex_object, " unless debugging is turned on, so I can feel free to make lots of logging statements!")
        if l.isSetDebug():
            l.debug("I do want to protect logging inside conditional if I need to log with ", slow_function_call())

`AppStatus` is a container for returning application status, such as warnings, errors, or other info along with the
main function result(s).  Log into it, just as with AppLogger.  These diagnostics can be logged or handled at higher levels in the call stack, providing for the principles of "effective logging" -
log only once, and with all context.  There are many more things we can do with status, merging status from
multiple call chains or de-duplicating log messages, but here is a basic usage:

```
            s = AppStatus()
            if s.ok: l.info("we're doing fine")
    
            s = AppStatus("unable to find boot sector")
            s.addWarn("backup all data now")
            print(str(s))
            if s.hasErrors(): l.error("We have a problem: ", str(s))  # shows whole status, inc. the warning
                return '''
demo: INFO: demo.py:57: we're doing fine
demo: ERROR: demo.py:61: We have a problem: demo.py:59: unable to find boot sector; WARNINGS: demo.py:60: backup all data now
'''
```

It also provides a mechanism for passing computed values up the call stack, either individually, or multiple values
  at once.  Think of it as a ledger to keep track of the things that happened so far in a given call chain.
  You don't have to make the hard choice of should I return a value, or should I throw an exception to indicate a 
  special condition.  You can report everything and let the caller decide, but if they forget to explicitly ignore
  errors, we'll still throw an exception.

```
        s = AppStatus()     # we can pretend we got this from a function call that returned an AppStatus
        s.setValue("foo")   # that function might have set a value that we want
        s.addErr("bar")     # but an error might have also been encountered
        v = s.getValue()    # in which case this would throw an exception
        s.clearErrors()     # unless clearErrors() called first
        getErrors()         # getErrors() indicates errors were handled and should not throw on getValue() (unimplemented?)
```

`AppError` is the same as `AppStatus`, but turned into an exception (with stack trace) for those times when you really
do want to throw an exception.  But, included with the exception you can still have your ledger of computed value(s) 
and other diagnostics you collected up to the failure point, like warnings and info messages.
  AppError doesn't inherit from AppStatus because AppStatus doesn't collect a stack trace, but AppError does.

Please see demo.py in this distribution for usage, starting from most basic and progressing to more advanced for all of the above and more.

===

CHANGELOG:

2.0.0:  Remove support for python 2
1.1.0:  Initial version.

