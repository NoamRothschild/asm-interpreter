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
    ParsingNotCompleted,
};

pub const ExecError = error{
    Halted,
    MissingOperand,
};
