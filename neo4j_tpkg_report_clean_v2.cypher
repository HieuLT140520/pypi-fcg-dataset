// neo4j_tpkg_report_clean_v2.cypher
// Report-ready Threat Pattern Knowledge Graph.
// IMPORTANT: every relationship statement MATCHes/MERGEs nodes explicitly.
// This avoids unlabeled anonymous nodes when executing statement-by-statement.

MATCH (n) DETACH DELETE n;

CREATE CONSTRAINT package_name IF NOT EXISTS FOR (p:Package) REQUIRE p.name IS UNIQUE;
CREATE CONSTRAINT behavior_name IF NOT EXISTS FOR (b:Behavior) REQUIRE b.name IS UNIQUE;
CREATE CONSTRAINT pattern_name IF NOT EXISTS FOR (pt:ThreatPattern) REQUIRE pt.name IS UNIQUE;

// ==========================
// Nodes
// ==========================
MERGE (:Package {name:'byteseep-99.7', label:'malicious', caption:'byteseep-99.7'});
MERGE (:Package {name:'rumdl-0.1.59', label:'benign', caption:'rumdl-0.1.59'});

MERGE (:Behavior {name:'ENTRY_POINT', caption:'ENTRY_POINT', risk:'context'});
MERGE (:Behavior {name:'ENV_DISCOVERY', caption:'ENV_DISCOVERY', risk:'medium'});
MERGE (:Behavior {name:'NETWORK_COMMUNICATION', caption:'NETWORK_COMMUNICATION', risk:'medium'});
MERGE (:Behavior {name:'FILE_SYSTEM_ACCESS', caption:'FILE_SYSTEM_ACCESS', risk:'low'});
MERGE (:Behavior {name:'DATA_EXFILTRATION', caption:'DATA_EXFILTRATION', risk:'high'});

MERGE (:ThreatPattern {name:'ENV_DISCOVERY_TO_NETWORK', caption:'ENV_DISCOVERY_TO_NETWORK', risk:'high'});
MERGE (:ThreatPattern {name:'LOCAL_FILE_SYSTEM_OPERATION', caption:'LOCAL_FILE_SYSTEM_OPERATION', risk:'low'});

// ==========================
// Package -> Behavior
// ==========================
MATCH (p:Package {name:'byteseep-99.7'}), (b:Behavior {name:'ENTRY_POINT'})
MERGE (p)-[:HAS_BEHAVIOR]->(b);

MATCH (p:Package {name:'byteseep-99.7'}), (b:Behavior {name:'ENV_DISCOVERY'})
MERGE (p)-[:HAS_BEHAVIOR]->(b);

MATCH (p:Package {name:'byteseep-99.7'}), (b:Behavior {name:'NETWORK_COMMUNICATION'})
MERGE (p)-[:HAS_BEHAVIOR]->(b);

MATCH (p:Package {name:'byteseep-99.7'}), (b:Behavior {name:'DATA_EXFILTRATION'})
MERGE (p)-[:HAS_BEHAVIOR]->(b);

MATCH (p:Package {name:'rumdl-0.1.59'}), (b:Behavior {name:'ENTRY_POINT'})
MERGE (p)-[:HAS_BEHAVIOR]->(b);

MATCH (p:Package {name:'rumdl-0.1.59'}), (b:Behavior {name:'FILE_SYSTEM_ACCESS'})
MERGE (p)-[:HAS_BEHAVIOR]->(b);

// ==========================
// Package -> Pattern
// ==========================
MATCH (p:Package {name:'byteseep-99.7'}), (pt:ThreatPattern {name:'ENV_DISCOVERY_TO_NETWORK'})
MERGE (p)-[:HAS_PATTERN]->(pt);

MATCH (p:Package {name:'rumdl-0.1.59'}), (pt:ThreatPattern {name:'LOCAL_FILE_SYSTEM_OPERATION'})
MERGE (p)-[:HAS_PATTERN]->(pt);

// ==========================
// Behavior -> Pattern -> Derived behavior
// ==========================
MATCH (b:Behavior {name:'ENV_DISCOVERY'}), (pt:ThreatPattern {name:'ENV_DISCOVERY_TO_NETWORK'})
MERGE (b)-[:COMPOSES_PATTERN]->(pt);

MATCH (b:Behavior {name:'NETWORK_COMMUNICATION'}), (pt:ThreatPattern {name:'ENV_DISCOVERY_TO_NETWORK'})
MERGE (b)-[:COMPOSES_PATTERN]->(pt);

MATCH (pt:ThreatPattern {name:'ENV_DISCOVERY_TO_NETWORK'}), (b:Behavior {name:'DATA_EXFILTRATION'})
MERGE (pt)-[:INDICATES]->(b);

MATCH (b:Behavior {name:'FILE_SYSTEM_ACCESS'}), (pt:ThreatPattern {name:'LOCAL_FILE_SYSTEM_OPERATION'})
MERGE (b)-[:COMPOSES_PATTERN]->(pt);

// Useful queries:
// MATCH p=(pkg:Package)-[:HAS_BEHAVIOR|HAS_PATTERN|COMPOSES_PATTERN|INDICATES*1..3]->(n)
// RETURN p;
//
// MATCH (n) RETURN labels(n) AS labels, count(n) AS count ORDER BY count DESC;
//
// MATCH ()-[r]->() RETURN type(r), count(r) ORDER BY count(r) DESC;
