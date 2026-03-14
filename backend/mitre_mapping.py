"""
MITRE ATT&CK Mapping Module
Maps malware families and threat indicators to MITRE ATT&CK Tactics and Techniques
"""

# Malware Family to MITRE ATT&CK Technique Mapping
# Based on common TTPs observed in the wild
MALWARE_TO_MITRE = {
    # APT Groups & Campaigns
    "apt1": {
        "tactics": ["Initial Access", "Execution", "Persistence", "Command and Control"],
        "techniques": ["T1566.001", "T1059.003", "T1053.005", "T1071.001"],
        "description": "Comment Crew - Chinese APT group"
    },
    "apt28": {
        "tactics": ["Initial Access", "Execution", "Credential Access"],
        "techniques": ["T1566.001", "T1059.001", "T1003.001"],
        "description": "Fancy Bear - Russian APT group"
    },
    "apt29": {
        "tactics": ["Initial Access", "Defense Evasion", "Command and Control"],
        "techniques": ["T1566.002", "T1027", "T1071.001"],
        "description": "Cozy Bear - Russian APT group"
    },
    
    # Common Malware Families
    "emotet": {
        "tactics": ["Initial Access", "Execution", "Lateral Movement"],
        "techniques": ["T1566.001", "T1059.003", "T1021.001"],
        "description": "Banking trojan and malware loader"
    },
    "trickbot": {
        "tactics": ["Execution", "Credential Access", "Lateral Movement"],
        "techniques": ["T1059.003", "T1003.001", "T1021.002"],
        "description": "Banking trojan and post-exploitation framework"
    },
    "mirai": {
        "tactics": ["Initial Access", "Impact"],
        "techniques": ["T1190", "T1498"],
        "description": "IoT botnet malware"
    },
    "wannacry": {
        "tactics": ["Initial Access", "Impact", "Lateral Movement"],
        "techniques": ["T1190", "T1486", "T1021.002"],
        "description": "Ransomware worm"
    },
    "ransomware": {
        "tactics": ["Impact", "Defense Evasion"],
        "techniques": ["T1486", "T1490"],
        "description": "Generic ransomware behavior"
    },
    "trojan": {
        "tactics": ["Execution", "Persistence", "Command and Control"],
        "techniques": ["T1059.003", "T1053.005", "T1071.001"],
        "description": "Generic trojan behavior"
    },
    "backdoor": {
        "tactics": ["Persistence", "Command and Control"],
        "techniques": ["T1543.003", "T1071.001"],
        "description": "Remote access backdoor"
    },
    "downloader": {
        "tactics": ["Execution", "Command and Control"],
        "techniques": ["T1059.003", "T1105"],
        "description": "Malware downloader/dropper"
    },
    "banker": {
        "tactics": ["Credential Access", "Collection"],
        "techniques": ["T1056.001", "T1113"],
        "description": "Banking trojan"
    },
    "spyware": {
        "tactics": ["Collection", "Exfiltration"],
        "techniques": ["T1056.001", "T1041"],
        "description": "Information stealer"
    },
    "adware": {
        "tactics": ["Execution", "Persistence"],
        "techniques": ["T1059.003", "T1547.001"],
        "description": "Adware/PUP"
    },
    "rootkit": {
        "tactics": ["Defense Evasion", "Persistence"],
        "techniques": ["T1014", "T1543.003"],
        "description": "Rootkit malware"
    },
    "worm": {
        "tactics": ["Lateral Movement", "Execution"],
        "techniques": ["T1021.002", "T1059.003"],
        "description": "Self-replicating worm"
    },
    "cryptominer": {
        "tactics": ["Impact", "Resource Development"],
        "techniques": ["T1496", "T1583.001"],
        "description": "Cryptocurrency miner"
    },
    "botnet": {
        "tactics": ["Command and Control", "Impact"],
        "techniques": ["T1071.001", "T1498"],
        "description": "Botnet malware"
    },
    "rat": {
        "tactics": ["Command and Control", "Collection"],
        "techniques": ["T1071.001", "T1113"],
        "description": "Remote Access Trojan"
    },
    "loader": {
        "tactics": ["Execution", "Defense Evasion"],
        "techniques": ["T1059.003", "T1027"],
        "description": "Malware loader"
    },
    
    # Specific malware variants
    "cobalt": {
        "tactics": ["Execution", "Command and Control", "Lateral Movement"],
        "techniques": ["T1059.001", "T1071.001", "T1021.001"],
        "description": "Cobalt Strike beacon"
    },
    "metasploit": {
        "tactics": ["Exploitation for Client Execution", "Command and Control"],
        "techniques": ["T1203", "T1071.001"],
        "description": "Metasploit framework"
    },
    "zeus": {
        "tactics": ["Credential Access", "Collection"],
        "techniques": ["T1056.001", "T1005"],
        "description": "Zeus banking trojan"
    },
    "dridex": {
        "tactics": ["Initial Access", "Credential Access"],
        "techniques": ["T1566.001", "T1056.001"],
        "description": "Dridex banking trojan"
    },
    "qakbot": {
        "tactics": ["Initial Access", "Lateral Movement"],
        "techniques": ["T1566.001", "T1021.002"],
        "description": "Qakbot/QBot malware"
    },
    "formbook": {
        "tactics": ["Collection", "Exfiltration"],
        "techniques": ["T1056.001", "T1041"],
        "description": "FormBook infostealer"
    },
    "agenttesla": {
        "tactics": ["Collection", "Credential Access"],
        "techniques": ["T1056.001", "T1555"],
        "description": "Agent Tesla keylogger"
    },
    "njrat": {
        "tactics": ["Command and Control", "Collection"],
        "techniques": ["T1071.001", "T1113"],
        "description": "njRAT remote access trojan"
    },
    "remcos": {
        "tactics": ["Command and Control", "Collection"],
        "techniques": ["T1071.001", "T1056.001"],
        "description": "Remcos RAT"
    },
}

# Threat category to generic MITRE mapping
THREAT_CATEGORY_TO_MITRE = {
    "phishing": {
        "tactics": ["Initial Access"],
        "techniques": ["T1566"],
        "description": "Phishing attack"
    },
    "malware": {
        "tactics": ["Execution"],
        "techniques": ["T1204"],
        "description": "Generic malware execution"
    },
    "c2": {
        "tactics": ["Command and Control"],
        "techniques": ["T1071"],
        "description": "Command and Control communication"
    },
    "exploit": {
        "tactics": ["Initial Access"],
        "techniques": ["T1190"],
        "description": "Exploit public-facing application"
    },
    "ddos": {
        "tactics": ["Impact"],
        "techniques": ["T1498"],
        "description": "Distributed Denial of Service"
    },
}


def get_mitre_ttps(malware_families: list, tags: list = [], categories: dict = {}) -> dict:
    """
    Get MITRE ATT&CK TTPs based on malware families, tags, and categories.
    
    Args:
        malware_families: List of malware family names (from VT, MB, etc.)
        tags: List of threat tags
        categories: Dict of threat categories
    
    Returns:
        Dict with tactics, techniques, and descriptions
    """
    tactics = set()
    techniques = set()
    descriptions = []
    
    # Process malware families
    if malware_families:
        for family in malware_families:
            family_lower = family.lower()
            for malware_key, mapping in MALWARE_TO_MITRE.items():
                if malware_key in family_lower or family_lower in malware_key:
                    tactics.update(mapping["tactics"])
                    techniques.update(mapping["techniques"])
                    descriptions.append(f"{family}: {mapping['description']}")
                    break
    
    # Process tags
    if tags:
        for tag in tags:
            tag_lower = tag.lower()
            for malware_key, mapping in MALWARE_TO_MITRE.items():
                if malware_key in tag_lower:
                    tactics.update(mapping["tactics"])
                    techniques.update(mapping["techniques"])
                    if f"{tag}: {mapping['description']}" not in descriptions:
                        descriptions.append(f"{tag}: {mapping['description']}")
                    break
    
    # Process categories
    if categories:
        for cat_key, cat_val in categories.items():
            cat_lower = str(cat_val).lower()
            for threat_cat, mapping in THREAT_CATEGORY_TO_MITRE.items():
                if threat_cat in cat_lower:
                    tactics.update(mapping["tactics"])
                    techniques.update(mapping["techniques"])
                    if mapping["description"] not in descriptions:
                        descriptions.append(mapping["description"])
    
    return {
        "tactics": sorted(list(tactics)),
        "techniques": sorted(list(techniques)),
        "descriptions": descriptions[:5],  # Limit to top 5
        "has_mapping": len(tactics) > 0 or len(techniques) > 0
    }


def enrich_with_mitre(intel_data: dict) -> dict:
    """
    Enrich intelligence data with MITRE ATT&CK mappings.
    
    Args:
        intel_data: Intelligence collection result from IntelCollector
    
    Returns:
        Enhanced dict with mitre_attack field
    """
    all_families = []
    all_tags = []
    all_categories = {}
    
    # Extract from all active sources
    feed_results = intel_data.get("feed_results", {})
    
    for source, result in feed_results.items():
        if result.get("status") == "ok":
            data = result.get("data", {})
            
            # Collect malware families
            families = data.get("malware_families", [])
            if families:
                all_families.extend(families)
            
            # Collect tags
            tags = data.get("tags", [])
            if tags:
                all_tags.extend(tags)
            
            # Collect categories
            cats = data.get("categories", {})
            if cats:
                all_categories.update(cats)
            
            # Also check suggested_threat_label from VT
            threat_label = data.get("suggested_threat_label", "")
            if threat_label:
                all_families.append(threat_label)
            
            # Check signature from MalwareBazaar
            signature = data.get("signature", "")
            if signature:
                all_families.append(signature)
    
    # Get MITRE mappings
    mitre_ttps = get_mitre_ttps(all_families, all_tags, all_categories)
    
    # Add to intel_data
    intel_data["mitre_attack"] = mitre_ttps
    
    return intel_data
