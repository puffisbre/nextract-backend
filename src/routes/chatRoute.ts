import express from 'express';
import { handleChat, getChatSessions, getChatSessionById } from '../controllers/chatController';

const router = express.Router();

router.post("/", handleChat);
router.get('/sessions', getChatSessions);
router.get('/session/:id', getChatSessionById);

export default router;