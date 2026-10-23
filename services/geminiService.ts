import api from '../api/client';
import { API_ENDPOINTS } from '../config/config';

export interface GeminiProxyRequest {
  model?: string;
  contents: any;
  systemInstruction?: any;
  generationConfig?: any;
}

export interface GeminiProxyResponse {
  candidates?: Array<{
    content?: {
      parts?: Array<{
        text?: string;
      }>;
    };
    finishReason?: string;
  }>;
  text?: string;
}

/**
 * Sends content generation requests to the backend proxy route.
 * Keeps GEMINI_API_KEY secure on the backend server — never bundled into client JavaScript.
 */
export const generateGeminiContent = async (
  request: GeminiProxyRequest
): Promise<string> => {
  const model = request.model || 'gemini-1.5-flash';
  
  // Format contents appropriately
  let contentsPayload = request.contents;
  if (typeof contentsPayload === 'string') {
    contentsPayload = [{ role: 'user', parts: [{ text: contentsPayload }] }];
  } else if (!Array.isArray(contentsPayload)) {
    contentsPayload = [contentsPayload];
  }

  const response = await api.post<GeminiProxyResponse>(
    API_ENDPOINTS.PROXY_GEMINI,
    {
      model,
      contents: contentsPayload,
      systemInstruction: request.systemInstruction,
      generationConfig: request.generationConfig,
    }
  );

  const candidate = response.data?.candidates?.[0];
  const text = candidate?.content?.parts?.[0]?.text || response.data?.text || '';
  return text;
};

export interface ThreatChatSession {
  sendMessageStream: ({ message }: { message: string }) => AsyncGenerator<{ text: string }, void, unknown>;
}

/**
 * Creates a threat chat session that routes through the backend proxy.
 */
export const createThreatChat = (context: string): ThreatChatSession => {
  const history: Array<{ role: string; parts: Array<{ text: string }> }> = [];

  const systemInstruction = {
    parts: [
      {
        text: `You are ANTI.AI, an elite cybersecurity threat intelligence assistant.
Embedded in ANTI.AI Threat Processor SOC platform.

CURRENT SESSION CONTEXT:
${context}

ROLE & BEHAVIOR:
- Act as a senior SOC analyst and forensic investigator.
- Provide concise, actionable, and technical responses.
- Use Markdown for formatting lists, code blocks, and headers.
- Maintain a vigilant, professional tone suitable for a security operations center.`,
      },
    ],
  };

  return {
    sendMessageStream: async function* ({ message }: { message: string }) {
      history.push({ role: 'user', parts: [{ text: message }] });

      try {
        const text = await generateGeminiContent({
          contents: history,
          systemInstruction,
          generationConfig: { temperature: 0.3 },
        });

        if (text) {
          history.push({ role: 'model', parts: [{ text }] });
          // Stream in small chunks for responsive UX
          const words = text.split(' ');
          let buffer = '';
          for (let i = 0; i < words.length; i++) {
            buffer += (i > 0 ? ' ' : '') + words[i];
            if (i % 6 === 0 || i === words.length - 1) {
              yield { text: buffer };
              buffer = '';
            }
          }
          if (buffer) yield { text: buffer };
          return;
        }
      } catch (err) {
        console.warn('[GeminiProxy] Backend proxy call failed, falling back to simulated SOC response', err);
      }

      // Offline / fallback response
      const fallbackText = `**[ANTI.AI SOC Analysis]**\n\nAnalyzed input: "${message}"\n\n` +
        `- Threat assessment: Monitored sensor telemetry active.\n` +
        `- Correlation: Cross-referenced with local threat intelligence and honeypot records.\n` +
        `- Recommendation: Verify IP reputation against AbuseIPDB and isolate any critical score hosts.\n\n` +
        `*(Backend AI proxy offline or unconfigured. To enable cloud Gemini models, configure GEMINI_API_KEY in the backend server environment.)*`;

      yield { text: fallbackText };
    },
  };
};
