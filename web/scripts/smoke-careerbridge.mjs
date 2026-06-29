const base = process.env.CAREERBRIDGE_BASE_URL || "http://127.0.0.1:5174";
const routes = ["/", "/login", "/jobs", "/verification", "/employer/dashboard", "/admin/passid"];
const failures = [];

for (const route of routes) {
  const res = await fetch(new URL(route, base));
  const text = await res.text();
  if (res.status >= 400) failures.push(`${route} returned ${res.status}`);
  if (!/CareerBridge|root|PASSID/i.test(text)) failures.push(`${route} did not look like CareerBridge HTML`);
}

const healthUrl = process.env.CAREERBRIDGE_API_URL ? new URL("/health", process.env.CAREERBRIDGE_API_URL) : null;
if (healthUrl) {
  const health = await fetch(healthUrl);
  const body = await health.json().catch(() => ({}));
  if (health.status !== 200 || body.service !== "careerbridge") failures.push("/health failed");
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(`CareerBridge smoke passed against ${base}`);
