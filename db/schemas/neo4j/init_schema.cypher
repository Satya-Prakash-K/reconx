// Neo4j Graph Schema for ReconX Attack Surface Mapping
// Run these Cypher commands to initialize the graph database

// ── Constraints (Unique Identifiers) ──────────────────

CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT subdomain_unique IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.name IS UNIQUE;
CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE;
CREATE CONSTRAINT port_unique IF NOT EXISTS FOR (p:Port) REQUIRE p.uid IS UNIQUE;
CREATE CONSTRAINT url_unique IF NOT EXISTS FOR (u:URL) REQUIRE u.value IS UNIQUE;
CREATE CONSTRAINT technology_unique IF NOT EXISTS FOR (t:Technology) REQUIRE t.name IS UNIQUE;
CREATE CONSTRAINT bucket_unique IF NOT EXISTS FOR (b:Bucket) REQUIRE b.name IS UNIQUE;
CREATE CONSTRAINT finding_unique IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE;
CREATE CONSTRAINT workspace_unique IF NOT EXISTS FOR (w:Workspace) REQUIRE w.id IS UNIQUE;

// ── Indexes (Performance) ─────────────────────────────

CREATE INDEX domain_workspace IF NOT EXISTS FOR (d:Domain) ON (d.workspace_id);
CREATE INDEX subdomain_workspace IF NOT EXISTS FOR (s:Subdomain) ON (s.workspace_id);
CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity);
CREATE INDEX ip_workspace IF NOT EXISTS FOR (i:IP) ON (i.workspace_id);

// ── Relationship Types ────────────────────────────────
// Domain -[:HAS_SUBDOMAIN]-> Subdomain
// Subdomain -[:SUBDOMAIN_OF]-> Domain
// Subdomain -[:RESOLVES_TO]-> IP
// IP -[:EXPOSES]-> Port
// Subdomain -[:HOSTS]-> URL
// Subdomain -[:USES]-> Technology
// Finding -[:AFFECTS]-> Subdomain
// Subdomain -[:LINKS_TO]-> URL
// Subdomain -[:HAS_BUCKET]-> Bucket
// Workspace -[:CONTAINS]-> Domain
