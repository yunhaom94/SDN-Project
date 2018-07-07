# debug variables and functions
VERBOSE_ON = False
DEBUG_ON = True

def _PRINT(*args, **kwargs): 
    if "func" in kwargs.keys():
        func = kwargs["func"]
    else:
        func = print

    if func == print:
        func(args[0])
    else:
        # let the function handles it
        func(*args)


def DEBUG(*args, **kwargs): 
    '''
    Example DEBUG("Things to print", my_print_arg1, func=myprint )
    or DEBUG("Thins to print") will call print function
    '''
    if DEBUG_ON:
        _PRINT(*args, **kwargs)

def VERBOSE(*args, **kwargs): 
    '''
    Example VERBOSE("Things to print", my_print_arg1, func=myprint )
    or DEBUG("Thins to print") will call print function
    '''
    if VERBOSE_ON:
        _PRINT(*args, **kwargs)