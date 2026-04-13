from app.schemas.scan import ModelInputPayload


def build_model_input(language: str, normalized_tokens: list[str]) -> ModelInputPayload:
    return ModelInputPayload(
        language=language,
        sequence=normalized_tokens,
        length=len(normalized_tokens),
    )