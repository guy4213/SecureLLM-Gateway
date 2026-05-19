import { RequestHandler } from 'express';
import { generateResponse } from '../services/llm.service';

interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
}

interface ChatRequest {
  model?: string;
  messages: ChatMessage[];
  temperature?: number;
  max_tokens?: number;
  stream?: boolean;
}

export const chatController: RequestHandler = async (req, res) => {
  const body = req.body as ChatRequest;
  const messages = body.messages ?? [];

  try {
    const completion = await generateResponse(
      messages,
      req.securityContext,
      req.client?.id,
      body.model,
      body.max_tokens
    );

    res.status(200).json(completion);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    if (req.securityContext) {
      req.securityContext.errorMessage = message;
    }

    if (message.startsWith('Service Unavailable')) {
      res.status(503).json({ error: 'Service Unavailable: upstream LLM call failed' });
      return;
    }

    res.status(500).json({ error: 'Internal Server Error' });
  }
};
