import { Request, Response } from "express";
import { Resend } from "resend";
import multer from "multer";

const apiKey = process.env.RESEND_API_KEY;

if (!apiKey) {
  throw new Error("RESEND_API_KEY is not defined in environment variables");
}

const storage = multer.memoryStorage();
export const upload = multer({ storage });

const resend = new Resend(apiKey);

export const sendEmail = async (req: Request, res: Response): Promise<void> => {
  try {
    const { name, subject, message, orgNumber } = req.body;
    const file = req.file;

    const attachments = [];

    if (file) {
      try {
        const base64 = file.buffer.toString("base64");

        attachments.push({
          filename: file.originalname,
          content: base64,
        });
      } catch (fileErr) {
        console.error("File processing error:", fileErr);
        res.status(400).json({ error: "Failed to process file" });
        return;
      }
    }

    const { data, error } = await resend.emails.send({
      from: "Contact Form <onboarding@resend.dev>",
      to: "william.gertoft@chasacademy.se",
      subject: `New message: ${subject}`,
      html: `
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Org Number:</strong> ${orgNumber}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong><br>${message}</p>
      `,
      attachments,
    });

    if (error) {
      console.error("Resend error:", error);
      res.status(500).json({ error: "Failed to send email" });
      return;
    }
    res.status(200).json({ success: true, data });
    return;
  } catch (err: any) {
    console.error("Unhandled error:", err);
    res.status(500).json({ error: "Unexpected server error" });
    return;
  }
};
