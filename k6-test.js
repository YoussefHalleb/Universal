import http from "k6/http";
import { check, sleep } from "k6";

const APP_URL = __ENV.APP_URL || "http://localhost:80";

export const options = {
  stages: [
    { duration: "30s", target: 10  },
    { duration: "1m",  target: 50  },
    { duration: "30s", target: 100 },
    { duration: "30s", target: 0   },
  ],
  thresholds: {
    http_req_duration: ["p(95)<2000"],
    http_req_failed:   ["rate<0.1"],
  },
};

export default function () {
  const res = http.get(APP_URL);
  check(res, {
    "status is 200":       (r) => r.status === 200,
    "response time < 2s":  (r) => r.timings.duration < 2000,
  });
  sleep(1);
}
