// Card layout mirrors the web UI (backend/web/index.html showResult):
// big score + verdict, explanation, then signals split into two groups by
// source — "Rule engine · deterministic" and "AI content analysis · LLM".

var _SEV_COLOR = { high: "#D32F2F", medium: "#E8820C", low: "#5F6368" };

function _sevChip(severity) {
  var sev = (severity || "low").toLowerCase();
  var color = _SEV_COLOR[sev] || _SEV_COLOR.low;
  return '<font color="' + color + '"><b>' + sev.toUpperCase() + '</b></font>';
}

function _renderSignals(section, signals) {
  if (!signals || signals.length === 0) {
    section.addWidget(
      CardService.newTextParagraph().setText('<font color="#5F6368">No signals.</font>')
    );
    return;
  }
  signals.forEach(function(signal) {
    section.addWidget(
      CardService.newDecoratedText()
        .setText(_sevChip(signal.severity) + "  " + signal.description)
        .setWrapText(true)
    );
  });
}

function buildCard(result) {
  var score       = result.score;
  var verdict     = result.verdict;
  var label       = result.verdict_label;
  var explanation = result.explanation;
  var signals     = result.signals || [];

  // Match the web: split by signal.source (default "rule").
  var ruleSigs = signals.filter(function(s) { return (s.source || "rule") !== "llm"; });
  var llmSigs  = signals.filter(function(s) { return (s.source || "rule") === "llm"; });

  var verdictIcon = verdict === "safe" ? "✅"
                  : verdict === "suspicious" ? "⚠️"
                  : "🚨";

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Security Score")
        .setSubtitle("Powered by AI analysis")
    );

  // Score + verdict + explanation (top block, like the web header)
  var scoreSection = CardService.newCardSection();
  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("VERDICT")
      .setText(verdictIcon + "  <b>" + label + "</b>")
      .setBottomLabel(score + " / 100")
      .setWrapText(false)
  );
  if (explanation) {
    scoreSection.addWidget(
      CardService.newTextParagraph().setText(explanation)
    );
  }
  card.addSection(scoreSection);

  // Rule engine · deterministic
  var ruleSection = CardService.newCardSection().setHeader("RULE ENGINE · DETERMINISTIC");
  _renderSignals(ruleSection, ruleSigs);
  card.addSection(ruleSection);

  // AI content analysis · LLM
  var llmSection = CardService.newCardSection().setHeader("AI CONTENT ANALYSIS · LLM");
  _renderSignals(llmSection, llmSigs);
  card.addSection(llmSection);

  return card.build();
}

function buildErrorCard(errorMessage) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Analysis Failed")
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph()
          .setText("Could not analyze this email. Error: " + errorMessage)
      )
    )
    .build();
}
