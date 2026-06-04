# Copyright 2026 Veritensor Security
import logging
from typing import List
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")
logger = logging.getLogger(__name__)

# None means "not checked yet"
PRESIDIO_AVAILABLE = None

class PIIScanner:
    _engine = None
    _init_error = None

    @classmethod
    def get_engine(cls):
        global PRESIDIO_AVAILABLE
        
        if PRESIDIO_AVAILABLE is None:
            try:
                # CRITICAL FIX: Lazy import inside the method to prevent DLL/OSError crashes on startup
                from presidio_analyzer import AnalyzerEngine
                from presidio_analyzer.nlp_engine import NlpEngineProvider
                import spacy
                from spacy.cli import download as spacy_download
                
                model_name = "en_core_web_sm"
                if not spacy.util.is_package(model_name):
                    logger.info(f"Downloading lightweight PII model ({model_name})...")
                    spacy_download(model_name)

                configuration = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model_name}],
                }
                provider = NlpEngineProvider(nlp_configuration=configuration)
                nlp_engine = provider.create_engine()

                cls._engine = AnalyzerEngine(
                    nlp_engine=nlp_engine,
                    supported_languages=["en"],
                    default_score_threshold=0.4
                )
                PRESIDIO_AVAILABLE = True
            except (ImportError, OSError, Exception) as e:
                # Catching OSError is crucial for broken C++ redistributables / c10.dll on Windows
                PRESIDIO_AVAILABLE = False
                cls._init_error = str(e)
                logger.debug(f"PII Engine Init Failed: {e}")

        return cls._engine

    @staticmethod
    def scan(text: str) -> List[str]:
        """Scans text for PII using ML. Returns list of threats."""
        engine = PIIScanner.get_engine()
        if not engine:
            return []

        threats = []
        try:
            text_sample = text[:100000] 
            results = engine.analyze(text=text_sample, language='en')
            
            for res in results:
                if res.score >= 0.5:
                    entity = text_sample[res.start:res.end]
                    masked = entity[:2] + "*" * (len(entity)-2) if len(entity) > 2 else "***"
                    threats.append(f"HIGH: PII Leak ({res.entity_type}): {masked}")
                    
        except Exception as e:
            logger.debug(f"PII Scan error: {e}")
            
        return threats
