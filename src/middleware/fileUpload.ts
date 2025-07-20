import multer from "multer";
import path from "path";

export const upload = multer({
  dest: "uploads/",
  fileFilter: (req, file, cb) => {
    const allowedExtensions = [".xml", ".csv", ".xlsx"];
    const ext = path.extname(file.originalname).toLowerCase();

    if (allowedExtensions.includes(ext)) {
      cb(null, true);
    } else {
      console.warn(`Rejected file upload: ${file.originalname}`);
      cb(null, false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 },
});

// File upload contact from
const memoryStorage = multer.memoryStorage();
export const contactUpload = multer({ storage: memoryStorage });
