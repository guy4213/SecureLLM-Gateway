import { Schema, model, Document, Types } from 'mongoose';

export type ApiKeyRole = 'client' | 'admin';

export interface IApiKey extends Document {
  _id: Types.ObjectId;
  /** SHA-256 hex digest of the raw key — never store the plaintext key */
  keyHash: string;
  /** Human-readable label for audit and admin UIs */
  name: string;
  role: ApiKeyRole;
  isActive: boolean;
  /** Override global rate limit for this key. null = use RATE_LIMIT_MAX_REQUESTS env default */
  rateLimitPerMinute: number | null;
  createdAt: Date;
  lastUsedAt: Date | null;
  /** Monotonically incrementing counter; updated asynchronously */
  requestCount: number;
}

const apiKeySchema = new Schema<IApiKey>(
  {
    keyHash: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      validate: {
        validator: (v: string): boolean => /^[a-f0-9]{64}$/.test(v),
        message: 'keyHash must be a lowercase SHA-256 hex string (64 chars)',
      },
    },
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 128,
    },
    role: {
      type: String,
      enum: ['client', 'admin'] satisfies ApiKeyRole[],
      required: true,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    rateLimitPerMinute: {
      type: Number,
      default: null,
      min: 1,
    },
    lastUsedAt: {
      type: Date,
      default: null,
    },
    requestCount: {
      type: Number,
      default: 0,
      min: 0,
    },
  },
  {
    // createdAt is managed by Mongoose; updatedAt is not needed here
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
    // Lean-friendly: disable Mongoose's built-in id getter duplication
    id: false,
  }
);

// Primary lookup path: auth middleware finds key by hash + active status
apiKeySchema.index({ keyHash: 1, isActive: 1 });

// Admin listing by role
apiKeySchema.index({ role: 1, isActive: 1 });

export const ApiKeyModel = model<IApiKey>('ApiKey', apiKeySchema);
