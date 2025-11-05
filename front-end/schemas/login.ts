import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email({ message: "Voer een geldig e-mailadres in" }),
  password: z.string().min(1, "Wachtwoord is vereist"),
});
