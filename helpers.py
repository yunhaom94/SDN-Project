# debug variables and functions


class Output():
    VERBOSE_ON = False
    DEBUG_ON = False

    @staticmethod
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

    @staticmethod
    def DEBUG(*args, **kwargs): 
        '''
        Example Output.DEBUG("Things to print", my_print_arg1, func=myprint )
        or Output.DEBUG("Thins to print") will call print function
        '''
        if Output.DEBUG_ON:
            Output._PRINT(*args, **kwargs)

    @staticmethod
    def VERBOSE(*args, **kwargs): 
        '''
        Example Output.VERBOSE("Things to print", my_print_arg1, func=myprint )
        or Output.DEBUG("Thins to print") will call print function
        '''
        if Output.VERBOSE_ON:
            Output._PRINT(*args, **kwargs)