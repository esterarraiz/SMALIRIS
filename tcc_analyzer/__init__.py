"""SMALIRIS — análise estática de risco em aplicações Android."""

__version__ = "1.0.0"

from .api_catalog import ApiCatalog, ApiRule, SmaliInvocation
from .code_analyzer import CodeAnalyzer
from .call_graph_analyzer import CallGraphAnalyzer
from .data_flow_analyzer import DataFlowAnalyzer
from .manifest_analyzer import ManifestAnalyzer
from .pipeline import AnalysisPipeline, PipelineResult
from .report_generator import ReportGenerator
from .report_schema import load_report_schema, validate_report
from .reverse_engineer import APKReverseEngineer
from .risk_correlator import RiskCorrelator
from .smali_locator import SmaliLocator

__all__ = [
    "APKReverseEngineer",
    "ApiCatalog",
    "ApiRule",
    "AnalysisPipeline",
    "CallGraphAnalyzer",
    "CodeAnalyzer",
    "DataFlowAnalyzer",
    "ManifestAnalyzer",
    "PipelineResult",
    "ReportGenerator",
    "RiskCorrelator",
    "SmaliLocator",
    "SmaliInvocation",
    "load_report_schema",
    "validate_report",
    "__version__",
]
