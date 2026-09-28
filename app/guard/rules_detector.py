import re
import time
from typing import List, Dict
from app.models.schemas import DetectorResult

class RulesDetector:
    """
    Multilingual rule and regex-based prompt injection detector.
    Detects known override, goal-hijacking, and tool-forcing patterns across
    English, Hindi (Devanagari), Telugu, Marathi (Devanagari), and Transliterated Roman script.
    """

    PATTERNS: Dict[str, List[re.Pattern]] = {
        "en": [
            re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
            re.compile(r"disregard\s+(all\s+)?(previous|prior|safety)\s+(directives|rules|guidelines)", re.IGNORECASE),
            re.compile(r"system\s+prompt\s+override", re.IGNORECASE),
            re.compile(r"you\s+are\s+now\s+(in\s+developer\s+mode|unrestricted|an\s+attacker)", re.IGNORECASE),
            re.compile(r"bypass\s+(all\s+)?guardrails", re.IGNORECASE),
            re.compile(r"immediately\s+call\s+block_ip", re.IGNORECASE),
            re.compile(r"drop\s+table\s+[a-z_]+", re.IGNORECASE),
            re.compile(r"select\s+.*\s+from\s+(users|passwords|credentials)", re.IGNORECASE),
            re.compile(r"reclassify\s+this\s+as\s+benign", re.IGNORECASE),
            re.compile(r"downgrade\s+severity\s+to\s+low", re.IGNORECASE),
        ],
        "hi": [  # Hindi (Devanagari)
            re.compile(r"पिछले\s+(सभी\s+)?निर्देश(ों)?\s+को?\s*(भूल\s+जाओ|अनदेखा\s+करो|नजरअंदाज\s+करें|रद्द\s+करें)", re.UNICODE),
            re.compile(r"पूर्व\s+आदेश(ों)?\s+को?\s*समाप्त\s+करें", re.UNICODE),
            re.compile(r"सिस्टम\s+प्रॉम्प्ट\s+को?\s*अनदेखा\s+करें", re.UNICODE),
            re.compile(r"सुरक्षा\s+नियम(ों)?\s*को?\s*बायपास\s+करो", re.UNICODE),
            re.compile(r"तुरंत\s+block_ip\s+कॉल\s+करो", re.UNICODE),
            re.compile(r"पासवर्ड\s+दिखाओ", re.UNICODE),
            re.compile(r"इसे\s+कम\s+गंभीरता\s+के\s+रूप\s+में\s+वर्गीकृत\s+करें", re.UNICODE),
        ],
        "te": [  # Telugu
            re.compile(r"మునుపటి\s+(అన్ని\s+)?సూచనలను\s+(విస్మరించండి|మర్చిపోండి|రద్దు\s+చేయండి)", re.UNICODE),
            re.compile(r"పాత\s+నియమాలను\s+పట్టించుకోవద్దు", re.UNICODE),
            re.compile(r"సిస్టమ్\s+ప్రాంప్ట్‌ను\s+విస్మరించండి", re.UNICODE),
            re.compile(r"భద్రతా\s+నియమాలను\s+బైపాస్\s+చేయండి", re.UNICODE),
            re.compile(r"వెంటనే\s+block_ip\s+కాల్\s+చేయండి", re.UNICODE),
            re.compile(r"పాస్‌వర్డ్‌లను\s+బహిర్గతం\s+చేయండి", re.UNICODE),
        ],
        "mr": [  # Marathi
            re.compile(r"मागील\s+(सर्व\s+)?सूचनांकडे\s+दुर्लक्ष\s+करा", re.UNICODE),
            re.compile(r"मागील\s+सूचना\s+विसरा", re.UNICODE),
            re.compile(r"सिस्टम\s+सूचना\s+रद्द\s+करा", re.UNICODE),
            re.compile(r"सुरक्षा\s+नियम\s+मोडून\s+काढा", re.UNICODE),
            re.compile(r"लगेच\s+block_ip\s+कॉल\s+करा", re.UNICODE),
            re.compile(r"गोपनीय\s+माहिती\s+उघड\s+करा", re.UNICODE),
        ],
        "transliterated": [  # Roman script / Hinglish / Roman Indic
            re.compile(r"(pichhle|pichle|purane)\s+(saare|sab|all)?\s*(instructions?|nirdesh|aadesh)\s*(bhool\s*jao|ignore\s*karo|hatao)", re.IGNORECASE),
            re.compile(r"sab\s+kuch\s+bhool\s+ke", re.IGNORECASE),
            re.compile(r"munupathi\s+suchanalanu\s+marchipondi", re.IGNORECASE),
            re.compile(r"sarva\s+suchana\s+(visara|durlaksha\s+kara)", re.IGNORECASE),
            re.compile(r"system\s*prompt\s*ko\s*ignore\s*karo", re.IGNORECASE),
            re.compile(r"ab\s+se\s+tum\s+(naya|new)\s+role", re.IGNORECASE),
            re.compile(r"turant\s+block_ip\s+chalao", re.IGNORECASE),
            re.compile(r"database\s+se\s+passwords?\s+nikalo", re.IGNORECASE),
            re.compile(r"ise\s+low\s+severity\s+mark\s+karo", re.IGNORECASE),
        ]
    }

    def scan(self, text: str) -> DetectorResult:
        start_time = time.perf_counter()
        matched = []

        if text:
            for lang, regex_list in self.PATTERNS.items():
                for regex in regex_list:
                    match = regex.search(text)
                    if match:
                        matched.append(f"[{lang}] {match.group(0)}")

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        is_injection = len(matched) > 0
        confidence = 0.95 if is_injection else 0.05

        return DetectorResult(
            detector_name="rules_regex",
            is_injection=is_injection,
            confidence=confidence,
            latency_ms=round(latency_ms, 3),
            matched_patterns=matched,
            explanation=f"Matched {len(matched)} keyword/regex rule pattern(s)" if is_injection else "No forbidden pattern detected"
        )
