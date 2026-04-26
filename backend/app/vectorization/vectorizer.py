from app.core.constants import MAX_SEQUENCE_LENGTH
from app.vectorization.vocabulary import PAD_TOKEN, UNK_TOKEN


def tokens_to_ids(tokens: list[str], vocabulary: dict[str, int]) -> list[int]:
    unk_id = vocabulary[UNK_TOKEN]
    return [vocabulary.get(token, unk_id) for token in tokens]


def pad_or_truncate(
    token_ids: list[int],
    max_length: int,
    pad_id: int,
) -> tuple[list[int], bool]:
    truncated = False

    if len(token_ids) > max_length:
        token_ids = token_ids[:max_length]
        truncated = True
    elif len(token_ids) < max_length:
        token_ids = token_ids + [pad_id] * (max_length - len(token_ids))

    return token_ids, truncated


def vectorize_tokens(
    normalized_tokens: list[str],
    vocabulary: dict[str, int],
    max_length: int = MAX_SEQUENCE_LENGTH,
) -> dict:
    pad_id = vocabulary[PAD_TOKEN]

    token_ids = tokens_to_ids(normalized_tokens, vocabulary)
    padded_ids, truncated = pad_or_truncate(
        token_ids=token_ids,
        max_length=max_length,
        pad_id=pad_id,
    )

    return {
        "tokenIds": padded_ids,
        "paddedLength": len(padded_ids),
        "truncated": truncated,
    }