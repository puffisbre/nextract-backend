import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

const prisma = new PrismaClient();

export const handleChat = async (req: Request, res: Response): Promise <any> => {
  const userInput = req.body.message;
  const userId = req.body.userId;
  const sessionId = req.body.sessionId;

  if (!userInput || !userId) {
    return res.status(400).json({ error: 'Missing message or userId' });
  }

  const promptPath = path.join(__dirname, '../utils/prompts/prompts.txt');
  const sitePrompt = fs.readFileSync(promptPath, 'utf-8');
  const prompt = `${sitePrompt}\n\nUser: ${userInput}\nAssistant:`;

  try {
    const ollamaRes = await axios.post('http://localhost:11434/api/generate', {
      model: 'llama3.2:latest',
      prompt,
      stream: false
    });

    const assistantReply = ollamaRes.data.response.trim();

    // ✅ NEW: If sessionId is provided → update
    if (sessionId) {
      const session = await prisma.chatSession.findUnique({ where: { id: sessionId } });

      if (!session) {
        return res.status(404).json({ error: 'Chat session not found' });
      }

      const currentMessages = session.messages as any[];
      const updatedMessages = [
        ...currentMessages,
        { role: 'user', content: userInput },
        { role: 'assistant', content: assistantReply },
      ];

      await prisma.chatSession.update({
        where: { id: session.id },
        data: { messages: updatedMessages },
      });

    } else {
      // ✅ NEW SESSION
      await prisma.chatSession.create({
        data: {
          userId,
          messages: [
            { role: 'assistant', content: 'Hi, how can I help you?' },
            { role: 'user', content: userInput },
            { role: 'assistant', content: assistantReply },
          ],
        },
      });
    }

    res.json({ reply: assistantReply });
  } catch (err) {
    console.error('Ollama API error:', err);
    res.status(500).json({ error: 'Failed to get response from Ollama' });
  }
};

// Get all chat sessions for user
export const getChatSessions = async (req: Request, res: Response): Promise<any> => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: "Missing userId" });

  try {
    const sessions = await prisma.chatSession.findMany({
      where: { userId: String(userId) },
      orderBy: { createdAt: 'desc' },
    });

    const history = sessions.map(session => {
      const messages = session.messages as any[];
      const firstUserMessage = messages?.find(m => m.role === 'user')?.content ?? "(No message)";
      return {
        id: session.id,
        createdAt: session.createdAt,
        preview: firstUserMessage
      };
    });

    res.json(history);
  } catch (err) {
    console.error('Get chat sessions error:', err);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
};

// Get full session by ID
export const getChatSessionById = async (req: Request, res: Response): Promise<any> => {
  const { id } = req.params;
  try {
    const session = await prisma.chatSession.findUnique({
      where: { id }
    });

    if (!session) return res.status(404).json({ error: 'Session not found' });

    res.json(session);
  } catch (err) {
    console.error('Get session error:', err);
    res.status(500).json({ error: 'Failed to fetch session' });
  }
};
