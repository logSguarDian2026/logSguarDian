import { extractFeatureVector, FEATURE_NAMES, CanonicalRequest } from "../src/index";

function vectorForBody(body: string, contentType: string): number[] {
  const req: Partial<CanonicalRequest> = {
    method: "POST",
    path: "/api/v1/sessions",
    body,
    contentType,
    userAgent: "axios/1.6.7",
  };
  return extractFeatureVector(req);
}

const NON_JSON_QUOTE_IDX = FEATURE_NAMES.indexOf("non_json_quote_count");
const QUOTE_IDX = FEATURE_NAMES.indexOf("quote_count");

describe("non_json_quote_count", () => {
  test("valid multi-field JSON body scores non_json_quote_count=0", () => {
    const body = JSON.stringify({
      request_id: "abc123",
      name: "sessions_42",
      status: "archived",
    });
    const vec = vectorForBody(body, "application/json");
    expect(vec[NON_JSON_QUOTE_IDX]).toBe(0);
    expect(vec[QUOTE_IDX]).toBeGreaterThan(0); // raw quote_count unchanged/still counts them
  });

  test("nested JSON body scores non_json_quote_count=0", () => {
    const body = JSON.stringify({
      name: "orders_1",
      metadata: { source: "api", version: "v1" },
    });
    const vec = vectorForBody(body, "application/json");
    expect(vec[NON_JSON_QUOTE_IDX]).toBe(0);
  });

  test("real SQLi quote-breakout payload keeps full signal (discount stays 0)", () => {
    const vec = vectorForBody("username=' OR 1=1--&password=x", "application/x-www-form-urlencoded");
    expect(vec[NON_JSON_QUOTE_IDX]).toBeGreaterThan(0);
  });

  test("SQLi payload embedded inside a JSON string value still keeps its quote signal", () => {
    const body = `{"username": "' OR 1=1--", "password": "x"}`;
    const vec = vectorForBody(body, "application/json");
    // 6 structural quotes (3 keys/values pairs minus the injected one) are
    // discounted, but the lone non-adjacent quote from the payload itself
    // survives - non_json_quote_count must stay > 0.
    expect(vec[NON_JSON_QUOTE_IDX]).toBeGreaterThan(0);
  });

  test("quote_count itself is unchanged (not replaced)", () => {
    const body = JSON.stringify({ a: "b" });
    const vec = vectorForBody(body, "application/json");
    expect(vec[QUOTE_IDX]).toBe(4); // "a", "b" -> 4 quote characters
  });
});
