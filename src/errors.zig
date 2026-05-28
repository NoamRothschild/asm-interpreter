pub const ParseError = error{
    UnknownInstruction,
    MismatchingOperandSizes,
    InvalidOperandType,
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
