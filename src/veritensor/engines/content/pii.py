# Copyright 2026 Veritensor Security
# PII Scanner wrapper around Microsoft Presidio (NLP-based)

import logging
from typing import List
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")

logger = logging.getLogger(__name__)

try:
    from presidio_analyzer import AnalyzerEngine
    import spacy
    from spacy.cli import download as spacy_download
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

class PIIScanner:
    _engine = None
    _init_error = None

    @classmethod
    def get_engine(cls):
        if not PRESIDIO_AVAILABLE:
            return None

        if cls._engine is None and cls._init_error is None:
            try:
                # Importing the provider
                from presidio_analyzer.nlp_engine import NlpEngineProvider
                
                model_name = "en_core_web_sm"
                if not spacy.util.is_package(model_name):
                    logger.info(f"Downloading lightweight PII model ({model_name})...")
                    spacy_download(model_name)

                # Правильная инициализация для новых версий Presidio
                configuration = {
                    "nlp_engine_name": "spacy",
                    "models":[{"lang_code": "en", "model_name": model_name}],
                }
                provider = NlpEngineProvider(nlp_configuration=configuration)
                nlp_engine = provider.create_engine()

                cls._engine = AnalyzerEngine(
                    nlp_engine=nlp_engine,
                    supported_languages=["en"],
                    default_score_threshold=0.4
                )
            except Exception as e:
                cls._init_error = str(e)
                logger.warning(f"PII Engine Init Failed: {e}")
        
        return cls._engine

    @staticmethod
    def scan(text: str) -> List[str]:
        """
        Scans text for PII using ML. Returns list of threats.
        """
        if not PRESIDIO_AVAILABLE:
            return []

        engine = PIIScanner.get_engine()
        if not engine:
            return []

        threats = []
        try:
            # Limit text length to avoid hanging on massive logs (100KB limit)
            text_sample = text[:100000] 
            results = engine.analyze(text=text_sample, language='en')
            
            for res in results:
                # Filter only confident matches
                if res.score >= 0.5:
                    entity = text_sample[res.start:res.end]
                    # Masking: Jo** instead of John (Privacy in logs)
                    masked = entity[:2] + "*" * (len(entity)-2) if len(entity) > 2 else "***"
                    threats.append(f"HIGH: PII Leak ({res.entity_type}): {masked}")
                    
        except Exception as e:
            logger.debug(f"PII Scan error: {e}")
            
        return threats
