import express from "express"
import { contactUpload } from '../middleware/fileUpload';
import { sendEmail } from '../controllers/EmailController';


const router = express.Router()

//Add email functionality if want to store support tickets
router.get("/", )
router.post('/', contactUpload.single('file'), sendEmail);



export default router; 