// Real-world FP shape from cal.com vital/save.ts: the handler uses
// req.body directly, but it's exported wrapped in `validate(handler)`
// where `validate` calls `Schema.parse(req.body)` before delegating.
// The body has been schema-checked by the time the handler runs, so
// the rule should NOT fire.

import type { NextApiRequest, NextApiResponse } from "next";
import { vitalSettingsUpdateSchema } from "./schema";
import { prisma } from "./db";

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  if (req.method === "PUT" && req.session?.user?.id) {
    const userId = req.session.user.id;
    const body = req.body;
    await prisma.user.update({
      where: { id: userId },
      data: {
        metadata: {
          vitalSettings: {
            ...body,
          },
        },
      },
    });
    res.status(200).end();
  }
};

function validate(
  handler: (req: NextApiRequest, res: NextApiResponse) => Promise<void>,
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    if (req.method === "POST" || req.method === "PUT") {
      try {
        vitalSettingsUpdateSchema.parse(req.body);
      } catch (err) {
        return res.status(400).json({ error: "Invalid body" });
      }
    } else {
      return res.status(405).end();
    }
    await handler(req, res);
  };
}

export default validate(handler);
