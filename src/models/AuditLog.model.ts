import { Schema, model, Document, Types } from 'mongoose';

export const THREAT_FLAGS = [
  'PROMPT_INJECTION_DETECTED',
  'PII_DETECTED',
  'OUTPUT_BLOCKED_SECRET_LEAK',
  'OUTPUT_BLOCKED_INJECTION_ECHO',
  'RATE_LIMIT_EXCEEDED',
  'AUTH_FAILURE',
  'MAX_TOKENS_EXCEEDED',
] as const;

export type ThreatFlag = (typeof THREAT_FLAGS)[number];

export interface IAuditLog extends Document {
  _id: Types.ObjectId;
  correlationId: string | null;
  timestamp: Date;
  /** FK reference — always set on authenticated requests */
  apiKeyId: Types.ObjectId | null;
  /** Stored separately so queries don't require a join */
  apiKeyHash: string | null;
  endpoint: string;
  httpMethod: string;
  /** SHA-256 of the sanitised (PII-redacted) request body */
  requestBodyHash: string | null;
  /** SHA-256 of the LLM response body (before output validation) */
  responseBodyHash: string | null;
  statusCode: number;
  /** Wall-clock latency from request receipt to response send */
  latencyMs: number;
  promptInjectionDetected: boolean;
  /** Which injection categories triggered (e.g. 'DIRECT_OVERRIDE') */
  injectionTypes: string[];
  piiDetected: boolean;
  /** Number of PII tokens replaced in the prompt */
  piiTokenCount: number;
  outputBlocked: boolean;
  sealedPiiMap: { iv: string; tag: string; data: string } | null;
  threatFlags: ThreatFlag[];
  llmProvider: string | null;
  llmModel: string | null;
  cacheHit: boolean;
  errorMessage: string | null;
}

const auditLogSchema = new Schema<IAuditLog>(
  {
    correlationId: {
      type: String,
      default: null,
      index: true,
    },
    timestamp: {
      type: Date,
      required: true,
      default: () => new Date(),
    },
    apiKeyId: {
      type: Schema.Types.ObjectId,
      ref: 'ApiKey',
      default: null,
    },
    apiKeyHash: {
      type: String,
      default: null,
    },
    endpoint: {
      type: String,
      required: true,
      maxlength: 512,
    },
    httpMethod: {
      type: String,
      required: true,
      uppercase: true,
      enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    },
    requestBodyHash: {
      type: String,
      default: null,
    },
    responseBodyHash: {
      type: String,
      default: null,
    },
    statusCode: {
      type: Number,
      required: true,
      min: 100,
      max: 599,
    },
    latencyMs: {
      type: Number,
      required: true,
      min: 0,
    },
    promptInjectionDetected: {
      type: Boolean,
      required: true,
      default: false,
    },
    injectionTypes: {
      type: [String],
      default: [],
    },
    piiDetected: {
      type: Boolean,
      required: true,
      default: false,
    },
    piiTokenCount: {
      type: Number,
      default: 0,
      min: 0,
    },
    outputBlocked: {
      type: Boolean,
      required: true,
      default: false,
    },
    sealedPiiMap: {
      type: new Schema(
        { iv: String, tag: String, data: String },
        { _id: false }
      ),
      default: null,
    },
    threatFlags: {
      type: [String],
      enum: THREAT_FLAGS,
      default: [],
    },
    llmProvider: {
      type: String,
      default: null,
    },
    llmModel: {
      type: String,
      default: null,
    },
    cacheHit: {
      type: Boolean,
      required: true,
      default: false,
    },
    errorMessage: {
      type: String,
      default: null,
      maxlength: 2048,
    },
  },
  {
    timestamps: false,
    versionKey: false,
    id: false,
  }
);

// TTL: auto-purge entries older than 90 days (GDPR / retention policy)
auditLogSchema.index(
  { timestamp: 1 },
  { expireAfterSeconds: 90 * 24 * 60 * 60, name: 'ttl_90d' }
);

// GET /v1/audit — paginated, descending, optionally filtered by key
auditLogSchema.index({ timestamp: -1, apiKeyId: 1 }, { name: 'audit_query' });

// Threat dashboard queries
auditLogSchema.index(
  { promptInjectionDetected: 1, timestamp: -1 },
  { name: 'threat_injection', sparse: true }
);
auditLogSchema.index(
  { outputBlocked: 1, timestamp: -1 },
  { name: 'threat_output', sparse: true }
);

export const AuditLogModel = model<IAuditLog>('AuditLog', auditLogSchema);
