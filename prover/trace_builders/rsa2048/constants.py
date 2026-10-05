# RSA-2048 Trace Constants

TRACE_WIDTH = 402
CYCLE_LENGTH = 256

# Transitions:
#   - Alignment     -> InitialAssertion
#   - IA            -> ConditionalMultiplication
#   - CM            -> ConditionalAssertion
#   - CA + 64       -> CR
#   - CR            -> CA   
#   - CA + 64 + M   -> Multiplication
#   - M             -> Assertion
#   - A + 64        -> Reduction
#   - R             -> Assertion
#   - A + 64 + M    -> CM
#   - A + 64 + ME   -> AlignmentStep

CONTROL_CODES = {
    "AlignmentStep": (0, 0, 0),
    "ConditionalMultiplication": (0, 0, 1),
    "ConditionalReduction": (0, 1, 0),
    "ConditionalAssertions": (0, 1, 1),
    "Multiplication": (1, 0, 0),
    "Reduction": (1, 0, 1),
    "Assertions": (1, 1, 0),
    "InitialAssertion": (1, 1, 1)
}

REGISTER_LIMIT = pow(2, 64)
REGISTER_MASK = 0xFFFFFFFFFFFFFFFF