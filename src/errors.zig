pub const ParseError = error{
    UnknownInstruction,
    MismatchingOperandSizes,
    InvalidOperandType,
    TwoMemoryOperands,
    ImmediateOutOfRange,
    UnknownLabel,
    InvalidExpression,
    InvalidEffectiveAddress,
    UnknownIndexingMode,
    UnknownOffsetLabel,
    ParsingIncomplete,
};

pub const ExecError = error{
    Halted,
    MissingOperand,
};
