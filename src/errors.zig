pub const ParseError = error{
    UnknownInstruction,
    MismatchingOperandSizes,
    InvalidOperandType,
    ImmediateOutOfRange,
    UnknownLabel,
    InvalidExpression,
    InvalidEffectiveAddress,
    UnknownIndexingMode,
};

pub const ExecError = error{
    Halted,
    MissingOperand,
};
