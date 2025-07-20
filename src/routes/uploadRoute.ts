import express from 'express';
import { upload } from '../middleware/fileUpload';
import { handleFileUpload } from '../controllers/uploadController';

const router = express.Router();

router.post('/', upload.single('file'), handleFileUpload);

export default router;