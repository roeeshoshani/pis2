#pragma once

#define _REC_MACRO_EVAL0(...) __VA_ARGS__
#define _REC_MACRO_EVAL1(...) _REC_MACRO_EVAL0(_REC_MACRO_EVAL0(_REC_MACRO_EVAL0(__VA_ARGS__)))
#define _REC_MACRO_EVAL2(...) _REC_MACRO_EVAL1(_REC_MACRO_EVAL1(_REC_MACRO_EVAL1(__VA_ARGS__)))
#define _REC_MACRO_EVAL3(...) _REC_MACRO_EVAL2(_REC_MACRO_EVAL2(_REC_MACRO_EVAL2(__VA_ARGS__)))
#define _REC_MACRO_EVAL4(...) _REC_MACRO_EVAL3(_REC_MACRO_EVAL3(_REC_MACRO_EVAL3(__VA_ARGS__)))

/// a macro which passes all inputs through the C pre-processor many times (365
/// times to be precise). this is used to expand recursive macros which require
/// many evaluation steps.
#define REC_MACRO_EVAL(...) _REC_MACRO_EVAL4(_REC_MACRO_EVAL4(_REC_MACRO_EVAL4(__VA_ARGS__)))

/// a function-like macro which evaluates to nothing. used to terminate
/// recursion.
#define _REC_MACRO_END_FN(...)

/// macro which evaluates to nothing. this is used to implement deferred
/// evaluation.
#define _REC_MACRO_EMPTY()

/// a recursive macro used to defer the evaluation of the given function-like macro.
#define _REC_MACRO_DEFER(FN) FN _REC_MACRO_EMPTY()

/// an argument used to mark the end of a recursive macro.
#define REC_MACRO_END ()

/// a function-like macro used to detect an end marker.
/// it is able to detect the end marker because when it is concatenated with an
/// and marker, it becomes a macro invokation.
#define _REC_MACRO_END_MARKER_DETECTOR(...) 0, _REC_MACRO_END_FN

/// returns the 2nd argument which should be a function-like macro and defers its evaluation.
#define _REC_MACRO_GET_2ND_ARG(IGNORED, FN, ...) _REC_MACRO_DEFER(FN)

/// evaluates all inputs by passing them once through the C pre-processor and
/// then returns the 2nd argument which should be a function-like macro and defers its evaluation.
#define _REC_MACRO_EVAL_AND_GET_2ND_ARG(IGNORED, FN) _REC_MACRO_GET_2ND_ARG(IGNORED, FN, 0)

/// a macro which returns the given `RESULT_FN` function-like macro if the given input `X` is not an
/// end marker. if the input is an end marker, returns a function-like macro which evaluates to
/// nothing to terminate recursion.
#define REC_MACRO_TEST(X, RESULT_FN)                                                               \
    _REC_MACRO_EVAL_AND_GET_2ND_ARG(_REC_MACRO_END_MARKER_DETECTOR X, RESULT_FN)

/// invokes the given function-like macro for each one of the arguments.
#define MAP(FN, ...) REC_MACRO_EVAL(_MAP_0(FN, ##__VA_ARGS__, REC_MACRO_END, 0))
#define _MAP_0(FN, CUR, NEXT, ...) FN(CUR) REC_MACRO_TEST(NEXT, _MAP_1)(FN, NEXT, ##__VA_ARGS__)
#define _MAP_1(FN, CUR, NEXT, ...) FN(CUR) REC_MACRO_TEST(NEXT, _MAP_0)(FN, NEXT, ##__VA_ARGS__)
