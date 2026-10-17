using System.Text.Json;
using AttackMap.NativeSpike;
int checks = 0;
void Check(bool result, string name) { if (!result) throw new Exception(name); checks++; }
string Format(string json) { using var document = JsonDocument.Parse(json); return FindingContextFormatter.Format(document.RootElement); }
string supplied = """{"context_version":"1.0","finding_id":"finding-č","claim":{"kind":"heuristic_static_analysis","text":"Český claim","runtime_verification":"unknown"},"priority":{"severity":"high","confidence":"low","score":17,"factors":[{"name":"severity","value":"high","source":"finding.severity","points":null}],"point_contributions":"not_supplied"},"source":{"role":"low_quality","locations":[{"file":"tests/ž.ts","line":7,"evidence_kind":"structured_location_reference"}],"policy":"attackmap.evidence.is_low_quality_source"},"evidence":{"candidates":[{"observation_id":"obs-č","association":"exact_location_candidate_only","ownership":"unknown","file":"tests/ž.ts","line":7,"conflicts":[{"field":"auth","values":["present","absent"]}],"origins":[{"analyzer":"node-service","analyzer_version":"1.2","metadata_status":"supplied"}]}],"candidates_truncated":true},"observed_controls":{"status":"unknown","items":[]},"trust_chain":{"status":"detector_owned_static_flow","source":"finding.code_flows","flows":[[{"file":"src/č.ts","line":1,"kind":"source"},{"file":"src/č.ts","line":9,"kind":"sink"}]],"trust_boundary_crossing":"unknown"},"uncertainty":["Synthetic static evidence; no runtime verification"]}""";
string text = Format(supplied);
foreach (string heading in new[] { "Claim", "Priority factors", "Source quality", "Candidate evidence", "Observed controls", "Trust chain", "Uncertainty" }) Check(text.Contains(heading), "heading " + heading);
foreach (string value in new[] { "finding-č", "Český claim", "severity: high", "confidence: low", "score: 17", "points: unknown (not supplied)", "point contributions: not_supplied", "tests/ž.ts", "observation id: obs-č", "exact_location_candidate_only", "ownership: unknown", "conflicts", "present", "absent", "node-service", "analyzer version: 1.2", "metadata status: supplied", "candidates truncated: true", "detector_owned_static_flow", "finding.code_flows", "src/č.ts", "sink", "trust boundary crossing: unknown" }) Check(text.Contains(value), "preserve " + value);
Check(text.Contains("Candidate evidence is not a verified association"), "candidate warning");
Check(!text.Contains("Display truncated"), "normal record not truncated");
string missing = Format("{\"context_version\":\"1.0\"}");
Check(missing.Contains("Trust chain\n  unknown (not supplied)") || missing.Contains("Trust chain\r\n  unknown (not supplied)"), "missing trust stays unknown");
Check(!missing.Contains("detector_owned_static_flow"), "missing flow never inferred");
Check(Format("null").Contains("unavailable"), "null context");
Check(Format("{}").Contains("unsupported or missing"), "missing version");
Check(Format("{\"context_version\":\"99\",\"claim\":\"untrusted version claim\"}").Contains("unavailable") && !Format("{\"context_version\":\"99\",\"claim\":\"untrusted version claim\"}").Contains("untrusted version claim"), "unknown version not interpreted");
Check(Format("{\"context_version\":\"1.0\",\"claim\":null}").Contains("unknown (not supplied)"), "null section");
string oversized = JsonSerializer.Serialize(new { context_version = "1.0", uncertainty = Enumerable.Repeat(new string('ž', 5000), 100).ToArray() });
string bounded = Format(oversized);
Check(bounded.Length <= FindingContextFormatter.MaximumCharacters && bounded.Contains("Display truncated"), "bounded output disclosed");
string nested = "{\"context_version\":\"1.0\",\"evidence\":" + string.Concat(Enumerable.Repeat("{\"nested\":", 20)) + "null" + new string('}',20) + "}";
Check(Format(nested).Contains("Display truncated"), "depth bound disclosed");
string unknown = Format("{\"context_version\":\"1.0\",\"trust_chain\":{\"status\":\"unknown\",\"flows\":[]},\"observed_controls\":{\"status\":\"unknown\",\"items\":[]}}");
Check(unknown.Contains("status: unknown") && !unknown.Contains("detector_owned_static_flow"), "unknown remains distinct from detector-owned flow");
Console.WriteLine($"PASS {checks} supplied finding context formatter checks");
