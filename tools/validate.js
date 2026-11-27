// Parses a .kql file with Microsoft's Kusto.Language and reports syntax + semantic
// diagnostics against a minimal Sentinel schema (OfficeActivity, SigninLogs).
// Usage: node validate.js <file.kql>
const fs = require("fs");
require("@kusto/language-service-next/bridge.min.js");
require("@kusto/language-service-next/Kusto.Language.Bridge.min.js");
const K = Kusto.Language;
const S = K.Symbols;

const T = { s: S.ScalarTypes.String, d: S.ScalarTypes.DateTime, dyn: S.ScalarTypes.Dynamic,
            i: S.ScalarTypes.Int, b: S.ScalarTypes.Bool };
const table = (name, cols) =>
  new S.TableSymbol.$ctor4(name, cols.map(([n, t]) => new S.ColumnSymbol(n, T[t])));

const officeActivity = table("OfficeActivity", [
  ["TimeGenerated","d"],["Operation","s"],["OfficeWorkload","s"],["RecordType","s"],
  ["UserId","s"],["UserType","s"],["ClientIP","s"],["Site_Url","s"],["Site_","s"],["SourceRecordId","s"],["SourceRelativeUrl","s"],
  ["SourceFileName","s"],["SourceFileExtension","s"],["OfficeObjectId","s"],["UserAgent","s"],
  ["OfficeId","s"],["OrganizationId","s"]]);
const signinLogs = table("SigninLogs", [
  ["TimeGenerated","d"],["UserPrincipalName","s"],["UserId","s"],["IPAddress","s"],
  ["ResultType","s"],["AppDisplayName","s"],["Location","s"],["LocationDetails","dyn"],
  ["AutonomousSystemNumber","s"],["RiskLevelDuringSignIn","s"],["UserType","s"]]);
const aadNonInteractive = table("AADNonInteractiveUserSignInLogs", [
  ["TimeGenerated","d"],["UserPrincipalName","s"],["UserId","s"],["IPAddress","s"],
  ["ResultType","s"],["AppDisplayName","s"],["Location","s"],["AutonomousSystemNumber","s"]]);

const db = new S.DatabaseSymbol.ctor("workspace", [officeActivity, signinLogs, aadNonInteractive]);
const globals = K.GlobalState.Default.WithDatabase(db);

// Stub for the Sentinel workspace function _GetWatchlist (validation only).
const STUB = "let _GetWatchlist = (alias:string) { datatable(SearchKey:string)[] };\n";
const src = fs.readFileSync(process.argv[2], "utf8");
const usesStub = src.includes("_GetWatchlist(") && !/let\s+_GetWatchlist/.test(src);
const text = (usesStub ? STUB : "") + src;
const lineOffset = usesStub ? 1 : 0;
const code = K.KustoCode.ParseAndAnalyze(text, globals);
const diags = code.GetDiagnostics();
const n = diags.Count;
if (n === 0) { console.log(`OK  ${process.argv[2]}: no syntax or semantic errors`); process.exit(0); }
for (let i = 0; i < n; i++) {
  const d = diags.getItem(i);
  const line = text.slice(0, d.Start).split("\n").length - lineOffset;
  console.log(`${d.Severity}  line ${line}: ${d.Message}  [${text.substr(d.Start, Math.max(d.Length,1)).trim()}]`);
}
process.exit(diags.Count ? 1 : 0);
