"""Validated data contracts for ML traffic classification.

These models describe the boundary between Go-generated flow metadata and the
future Python inference service. They intentionally contain no ML logic.
"""

from __future__ import annotations

from enum import StrEnum
from math import isfinite

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TrafficClass(StrEnum):
    """Traffic classes supported by the initial classifier."""

    WEB = "web"
    VIDEO = "video"
    VOIP = "voip"
    EMAIL = "email"
    FILE_TRANSFER = "file_transfer"
    MESSAGING = "messaging"
    ICMP = "icmp"
    UNKNOWN = "UNKNOWN"


class FlowFeatures(BaseModel):
    """Metadata-derived features for one encrypted traffic flow."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    flow_id: str = Field(min_length=1)
    window_id: str = Field(default="", max_length=200)
    aggregation_scope: str = Field(
        default="aggregate_endpoint_channel_estimate",
        pattern="^(aggregate_endpoint_channel_estimate|paired_bidirectional_sa_channel)$",
    )
    duration: float = Field(gt=0)
    packet_count: int = Field(ge=1)
    total_bytes: int = Field(ge=0)
    packets_per_second: float = Field(ge=0)
    bytes_per_second: float = Field(ge=0)
    mean_packet_size: float = Field(ge=0)
    std_packet_size: float = Field(ge=0)
    min_packet_size: float = Field(ge=0)
    max_packet_size: float = Field(ge=0)
    p25_packet_size: float = Field(ge=0)
    median_packet_size: float = Field(ge=0)
    p75_packet_size: float = Field(ge=0)
    p95_packet_size: float = Field(ge=0)
    mean_interarrival_time: float = Field(ge=0)
    std_interarrival_time: float = Field(ge=0)
    upload_packets: int = Field(ge=0)
    download_packets: int = Field(ge=0)
    upload_bytes: int = Field(ge=0)
    download_bytes: int = Field(ge=0)
    upload_download_ratio: float = Field(ge=0)
    burst_count: int = Field(ge=0)
    mean_burst_size: float = Field(ge=0)
    idle_time_ratio: float = Field(ge=0, le=1)

    @field_validator("flow_id")
    @classmethod
    def flow_id_must_not_be_blank(cls, value: str) -> str:
        if not value:
            raise ValueError("flow_id must not be blank")
        return value

    @field_validator("*")
    @classmethod
    def numeric_values_must_be_finite(cls, value: object) -> object:
        if isinstance(value, float) and not isfinite(value):
            raise ValueError("numeric values must be finite")
        return value

    @model_validator(mode="after")
    def validate_feature_relationships(self) -> "FlowFeatures":
        if self.upload_packets + self.download_packets != self.packet_count:
            raise ValueError("directional packet counts must equal packet_count")
        if self.upload_bytes + self.download_bytes != self.total_bytes:
            raise ValueError("directional byte counts must equal total_bytes")

        packet_size_percentiles = (
            self.min_packet_size,
            self.p25_packet_size,
            self.median_packet_size,
            self.p75_packet_size,
            self.p95_packet_size,
            self.max_packet_size,
        )
        if packet_size_percentiles != tuple(sorted(packet_size_percentiles)):
            raise ValueError("packet-size percentiles must be ordered from min to max")
        return self


class ClassPrediction(BaseModel):
    """One ranked class and its model confidence."""

    model_config = ConfigDict(extra="forbid")

    traffic_class: TrafficClass
    confidence: float = Field(ge=0, le=1)

    @field_validator("confidence")
    @classmethod
    def confidence_must_be_finite(cls, value: float) -> float:
        if not isfinite(value):
            raise ValueError("confidence must be finite")
        return value


class FeatureExplanation(BaseModel):
    """A feature's contribution to one prediction.

    Impact is intentionally signed: positive and negative values can
    respectively support or oppose the predicted class.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    feature: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    value: float
    impact: float
    direction: str = Field(pattern="^(supports_prediction|opposes_prediction|neutral)$")

    @field_validator("feature")
    @classmethod
    def feature_must_not_be_blank(cls, value: str) -> str:
        if not value:
            raise ValueError("feature must not be blank")
        return value

    @field_validator("value", "impact")
    @classmethod
    def explanation_numbers_must_be_finite(cls, value: float) -> float:
        if not isfinite(value):
            raise ValueError("explanation values must be finite")
        return value


class PredictionResult(BaseModel):
    """Inference response for one flow, independent of model implementation."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    flow_id: str = Field(min_length=1)
    window_id: str = Field(default="", max_length=200)
    aggregation_scope: str = Field(
        default="aggregate_endpoint_channel_estimate",
        pattern="^(aggregate_endpoint_channel_estimate|paired_bidirectional_sa_channel)$",
    )
    predicted_class: TrafficClass
    confidence: float = Field(ge=0, le=1)
    is_unknown: bool
    top_predictions: list[ClassPrediction] = Field(min_length=3, max_length=3)
    model_version: str = Field(min_length=1)
    top_explanations: list[FeatureExplanation] = Field(default_factory=list)
    inference_time_ms: float = Field(ge=0)

    @field_validator("flow_id", "model_version")
    @classmethod
    def required_strings_must_not_be_blank(cls, value: str) -> str:
        if not value:
            raise ValueError("value must not be blank")
        return value

    @field_validator("confidence", "inference_time_ms")
    @classmethod
    def response_numbers_must_be_finite(cls, value: float) -> float:
        if not isfinite(value):
            raise ValueError("numeric values must be finite")
        return value

    @model_validator(mode="after")
    def validate_unknown_state_and_ranking(self) -> "PredictionResult":
        if self.is_unknown != (self.predicted_class is TrafficClass.UNKNOWN):
            raise ValueError("is_unknown must match whether predicted_class is UNKNOWN")
        if not self.is_unknown and self.top_predictions[0].traffic_class is not self.predicted_class:
            raise ValueError("first top prediction must match predicted_class")
        if self.is_unknown and any(
            prediction.traffic_class is TrafficClass.UNKNOWN
            for prediction in self.top_predictions
        ):
            raise ValueError("UNKNOWN is a rejection outcome, not a model class probability")
        if any(
            later.confidence > earlier.confidence
            for earlier, later in zip(self.top_predictions, self.top_predictions[1:])
        ):
            raise ValueError("top_predictions must be ordered by descending confidence")
        return self
