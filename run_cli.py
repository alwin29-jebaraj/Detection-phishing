"""
Helper CLI utility invoked by the server to run deterministic Python analysis.
Reads JSON from stdin, executes rule engine, and writes JSON to stdout.
"""
import sys
import json
from analyzers.rule_engine import run_email_rules
from analyzers.url_analyzer import analyze_url
from scoring.risk_scorer import calculate_risk_score, generate_recommendation, generate_text_report

def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input:
            print(json.dumps({"error": "No input provided"}), file=sys.stderr)
            sys.exit(1)

        payload = json.loads(raw_input)
        mode = payload.get("mode", "email")

        if mode == "email":
            content = payload.get("content", "")
            indicators, extracted_urls = run_email_rules(content)
            score, level, breakdown = calculate_risk_score(indicators)
            rec = generate_recommendation(level, indicators)
            
            primary_url_analysis = None
            if extracted_urls:
                primary_url_analysis = analyze_url(extracted_urls[0]).to_dict()

            report = generate_text_report(
                input_type="email",
                input_data=content,
                risk_score=score,
                risk_level=level,
                indicators=indicators,
                recommendation=rec
            )

            result = {
                "input_type": "email",
                "input_data": content,
                "risk_score": score,
                "risk_level": level,
                "indicators": [ind.to_dict() for ind in indicators],
                "score_breakdown": breakdown,
                "extracted_urls": extracted_urls,
                "url_analysis": primary_url_analysis,
                "recommendation": rec,
                "ascii_report": report
            }
            print(json.dumps(result))

        elif mode == "url":
            target_url = payload.get("url", "")
            url_res = analyze_url(target_url)
            score, level, breakdown = calculate_risk_score(url_res.indicators)
            rec = generate_recommendation(level, url_res.indicators)

            report = generate_text_report(
                input_type="url",
                input_data=target_url,
                risk_score=score,
                risk_level=level,
                indicators=url_res.indicators,
                recommendation=rec
            )

            result = {
                "input_type": "url",
                "input_data": target_url,
                "risk_score": score,
                "risk_level": level,
                "indicators": [ind.to_dict() for ind in url_res.indicators],
                "score_breakdown": breakdown,
                "url_analysis": url_res.to_dict(),
                "recommendation": rec,
                "ascii_report": report
            }
            print(json.dumps(result))

        else:
            print(json.dumps({"error": f"Unsupported mode: {mode}"}), file=sys.stderr)
            sys.exit(1)

    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
