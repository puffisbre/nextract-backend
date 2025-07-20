import express from 'express';
import { contactUpload } from '../middleware/fileUpload';
import { sendEmail } from '../controllers/EmailController';

const router = express.Router();

router.post('/', contactUpload.single('file'), sendEmail);

export default router;





