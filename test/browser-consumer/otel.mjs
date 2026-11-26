import { trace } from '@opentelemetry/api';
import { createOtelTracer } from '@vericerts/vericerts-wallet-sdk/otel';

const tracer = createOtelTracer(trace.getTracer('sdk-browser-consumer'), true);
const span = tracer.startSpan('browser');
span.end();
document.documentElement.dataset.sdkResult = 'pass';
