import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
import multer from "multer";
import crypto from "node:crypto";
import { verifyToken } from "@clerk/backend";
import slugify from "slugify";

const app = express();
const PORT = process.env.PORT || 5000;

// Allow All Origins
app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json({ limit: "12mb" }));

// MongoDB connection
const client = new MongoClient(
  process.env.MONGO_URL || "mongodb://127.0.0.1:27017"
);

await client.connect();

const db = client.db(process.env.DB_NAME || "entrepreneur_desk");

const col = (name) => db.collection(name);
const uid = () => crypto.randomUUID();
const now = () => new Date();

const live = {
  status: "published",
  deleted: { $ne: true },
};

const notDeleted = {
  deleted: { $ne: true },
};

const safe = ({ _id, ...x }) => x;

const makeSlug = (s) =>
  slugify(String(s || "").trim(), {
    lower: true,
    strict: true,
  }).slice(0, 110) || uid();

async function uniqueSlug(collection, raw, id) {
  const base = makeSlug(raw);
  let s = base;
  let n = 2;

  while (
    await collection.findOne({
      slug: s,
      ...(id ? { id: { $ne: id } } : {}),
    })
  ) {
    s = `${base}-${n++}`;
  }

  return s;
}

// Authentication
async function authenticate(req, res, next) {
  try {
    const h = req.headers.authorization || "";

    const token = h.startsWith("Bearer ")
      ? h.slice(7)
      : req.cookies?.__session;

    if (!token) {
      return res.status(401).json({
        detail: "Not signed in",
      });
    }

    if (!process.env.CLERK_SECRET_KEY) {
      return res.status(503).json({
        detail: "Clerk is not configured",
      });
    }

    const claims = await verifyToken(token, {
      secretKey: process.env.CLERK_SECRET_KEY,
    });

    const userId = claims.sub;

    if (!userId) {
      throw Error("No user id");
    }

    let member = await col("users").findOne({
      user_id: userId,
    });

    if (!member) {
      let email = "";
      let name = "";

      try {
        const r = await fetch(
          `https://api.clerk.com/v1/users/${userId}`,
          {
            headers: {
              Authorization: `Bearer ${process.env.CLERK_SECRET_KEY}`,
            },
          }
        );

        const u = await r.json();

        email =
          u.email_addresses
            ?.find((e) => e.id === u.primary_email_address_id)
            ?.email_address?.toLowerCase() || "";

        name = [u.first_name, u.last_name]
          .filter(Boolean)
          .join(" ");
      } catch (e) {
        console.error("Clerk user fetch error:", e);
      }

      const admins = (process.env.ADMIN_EMAIL || "")
        .split(",")
        .map((x) => x.trim().toLowerCase());

      const role = admins.includes(email)
        ? "admin"
        : email && (await col("author_invites").findOne({ email }))
          ? "author"
          : "pending";

      member = {
        user_id: userId,
        email,
        name,
        role,
        created_at: now(),
        env: process.env.CLERK_PUBLISHABLE_KEY?.startsWith("pk_live_")
          ? "live"
          : "preview",
      };

      await col("users").insertOne(member);
    }

    req.member = {
      ...member,
      _id: undefined,
    };

    next();
  } catch (e) {
    console.error("AUTH ERROR:", e);

    res.status(401).json({
      detail: "Invalid or expired session",
    });
  }
}

const staff = (req, res, next) => {
  if (!["admin", "author"].includes(req.member?.role)) {
    return res.status(403).json({
      detail: "Not allowed",
    });
  }

  next();
};

const admin = (req, res, next) => {
  if (req.member?.role !== "admin") {
    return res.status(403).json({
      detail: "Not allowed",
    });
  }

  next();
};

const scope = (req) =>
  req.member.role === "admin"
    ? {}
    : { author_id: req.member.user_id };

// Public API
app.get("/api/", (req, res) => {
  res.json({
    message: "Entrepreneur Desk API",
  });
});

app.get("/api/clerk/config", (req, res) => {
  res.json({
    enabled: !!(
      process.env.CLERK_PUBLISHABLE_KEY &&
      process.env.CLERK_SECRET_KEY
    ),
    publishable_key: process.env.CLERK_PUBLISHABLE_KEY || "",
    proxy_url: "",
  });
});

app.get("/api/me", authenticate, (req, res) => {
  res.json({
    user_id: req.member.user_id,
    email: req.member.email || "",
    name: req.member.name || "",
    role: req.member.role,
  });
});

app.post("/api/auth/logout", (req, res) => {
  res.json({ ok: true });
});

// Users
app.get("/api/users", authenticate, admin, async (req, res) => {
  res.json({
    roles: ["admin", "author", "pending"],
    users: await col("users")
      .find(
        {},
        {
          projection: {
            _id: 0,
            user_id: 1,
            email: 1,
            name: 1,
            role: 1,
          },
        }
      )
      .sort({ created_at: -1 })
      .toArray(),
  });
});

app.patch(
  "/api/users/:user_id/role",
  authenticate,
  admin,
  async (req, res) => {
    if (!["admin", "author", "pending"].includes(req.body.role)) {
      return res.status(422).json({
        detail: "Invalid role",
      });
    }

    const target = await col("users").findOne({
      user_id: req.params.user_id,
    });

    if (!target) {
      return res.status(404).json({
        detail: "Not found",
      });
    }

    if (
      target.role === "admin" &&
      req.body.role !== "admin" &&
      (await col("users").countDocuments({ role: "admin" })) <= 1
    ) {
      return res.status(409).json({
        detail: "Keep at least one admin",
      });
    }

    await col("users").updateOne(
      { user_id: req.params.user_id },
      { $set: { role: req.body.role } }
    );

    res.json({
      user_id: req.params.user_id,
      role: req.body.role,
    });
  }
);

// Settings
app.get("/api/settings", async (req, res) => {
  res.json(
    (await col("settings").findOne(
      { id: "site" },
      { projection: { _id: 0 } }
    )) || {}
  );
});

// Categories
app.get("/api/categories", async (req, res) => {
  const cats = await col("categories")
    .find({}, { projection: { _id: 0 } })
    .sort({ name: 1 })
    .toArray();

  const counts = await col("posts")
    .aggregate([
      {
        $match: {
          ...live,
          type: { $in: ["story", "interview"] },
        },
      },
      {
        $group: {
          _id: "$category",
          n: { $sum: 1 },
        },
      },
    ])
    .toArray();

  const map = Object.fromEntries(
    counts.map((x) => [x._id, x.n])
  );

  res.json(
    cats.map((c) => ({
      ...c,
      post_count: map[c.name] || 0,
    }))
  );
});

// Stories
app.get("/api/stories", async (req, res) => {
  const q = {
    ...live,
    type:
      req.query.type &&
      ["story", "interview"].includes(req.query.type)
        ? req.query.type
        : { $in: ["story", "interview"] },
  };

  if (req.query.category && req.query.category !== "All") {
    q.category = req.query.category;
  }

  if (req.query.q) {
    const rx = new RegExp(
      String(req.query.q).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
      "i"
    );

    q.$or = [
      "title",
      "dek",
      "person",
      "company",
      "category",
      "author",
      "tags",
    ].map((k) => ({
      [k]: rx,
    }));
  }

  res.json(
    await col("posts")
      .find(q, { projection: { _id: 0 } })
      .sort({ published_at: -1 })
      .limit(300)
      .toArray()
  );
});

app.get("/api/stories/:slug", async (req, res) => {
  const p = await col("posts").findOne(
    {
      ...live,
      slug: req.params.slug,
    },
    {
      projection: { _id: 0 },
    }
  );

  if (!p) {
    return res.status(404).json({
      detail: "Story not found",
    });
  }

  res.json(p);
});

// News
app.get("/api/news", async (req, res) => {
  const q = {
    ...live,
    type: "news",
  };

  if (req.query.region && req.query.region !== "Global") {
    q.region = req.query.region;
  }

  res.json(
    await col("posts")
      .find(q, { projection: { _id: 0 } })
      .sort({ published_at: -1 })
      .limit(300)
      .toArray()
  );
});

// Lists
app.get("/api/lists", async (req, res) => {
  const docs = await col("lists")
    .find(live, { projection: { _id: 0 } })
    .sort({ year: -1 })
    .toArray();

  res.json(
    docs.map((d) => ({
      id: d.id,
      slug: d.slug,
      title: d.title,
      year: d.year,
      description: d.description || "",
      count: d.entries?.length || 0,
      status: d.status,
    }))
  );
});

app.get("/api/lists/:slug", async (req, res) => {
  const d = await col("lists").findOne(
    {
      ...live,
      slug: req.params.slug,
    },
    {
      projection: { _id: 0 },
    }
  );

  if (!d) {
    return res.status(404).json({
      detail: "List not found",
    });
  }

  res.json(d);
});

// Newsletter
app.post("/api/newsletter", async (req, res) => {
  const email = String(req.body.email || "")
    .trim()
    .toLowerCase();

  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(422).json({
      detail: "Valid email required",
    });
  }

  const old = await col("newsletter").findOne({ email });

  if (old) {
    return res.json({
      email,
      already_subscribed: true,
    });
  }

  await col("newsletter").insertOne({
    email,
    created_at: now(),
  });

  res.json({
    email,
    already_subscribed: false,
  });
});

// Nominations
app.post("/api/nominations", async (req, res) => {
  const b = req.body;

  if (
    !b.full_name ||
    !b.email ||
    !b.company ||
    String(b.pitch || "").length < 20
  ) {
    return res.status(422).json({
      detail: "Please complete all required fields",
    });
  }

  const d = {
    id: uid(),
    ...b,
    created_at: now(),
  };

  await col("nominations").insertOne(d);

  res.status(201).json(safe(d));
});

// Admin dashboard and CMS
app.use("/api/admin", authenticate, staff);

app.get("/api/admin/stats", async (req, res) => {
  const s = {
    ...notDeleted,
    ...scope(req),
  };

  res.json({
    posts: await col("posts").countDocuments(s),
    published: await col("posts").countDocuments({
      ...s,
      status: "published",
    }),
    drafts: await col("posts").countDocuments({
      ...s,
      status: "draft",
    }),
    scheduled: await col("posts").countDocuments({
      ...s,
      status: "scheduled",
    }),
    categories: await col("categories").countDocuments({}),
    lists: await col("lists").countDocuments(notDeleted),
    media: await col("media").countDocuments({
      is_deleted: false,
    }),
    subscribers:
      req.member.role === "admin"
        ? await col("newsletter").countDocuments({})
        : 0,
    nominations:
      req.member.role === "admin"
        ? await col("nominations").countDocuments({})
        : 0,
  });
});

// Admin posts
app.get("/api/admin/posts", async (req, res) => {
  const q = {
    ...notDeleted,
    ...scope(req),
  };

  if (["draft", "published", "scheduled"].includes(req.query.status)) {
    q.status = req.query.status;
  }

  if (["story", "interview", "news"].includes(req.query.type)) {
    q.type = req.query.type;
  }

  if (req.query.q) {
    q.$or = ["title", "person", "company", "author"].map((k) => ({
      [k]: new RegExp(String(req.query.q), "i"),
    }));
  }

  res.json(
    await col("posts")
      .find(q, { projection: { _id: 0 } })
      .sort({ updated_at: -1 })
      .limit(1000)
      .toArray()
  );
});

app.get("/api/admin/posts/:id", async (req, res) => {
  const p = await col("posts").findOne(
    {
      id: req.params.id,
      ...notDeleted,
      ...scope(req),
    },
    {
      projection: { _id: 0 },
    }
  );

  if (!p) {
    return res.status(404).json({
      detail: "Not found",
    });
  }

  res.json(p);
});

// Prepare post data
function prepare(b, old = {}) {
  const d = { ...b };

  d.tags = Array.isArray(d.tags)
    ? d.tags.map((x) => String(x).trim()).filter(Boolean)
    : [];

  d.updated_at = now();

  if (d.status === "published") {
    d.scheduled_at = "";
    d.published_at =
      d.published_at ||
      old.published_at ||
      now().toISOString().slice(0, 10);
  }

  if (d.status === "scheduled") {
    const t = new Date(d.scheduled_at);

    if (!d.scheduled_at || isNaN(t) || t <= now()) {
      throw Object.assign(
        Error("Scheduled time must be in the future"),
        { status: 422 }
      );
    }

    d.scheduled_at = t.toISOString();
    d.published_at = t.toISOString().slice(0, 10);
  }

  if (!d.dek && d.content_html) {
    d.dek = d.content_html
      .replace(/<[^>]*>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 200);
  }

  const words = (d.content_html || "")
    .replace(/<[^>]*>/g, " ")
    .split(/\s+/)
    .filter(Boolean).length;

  d.read_minutes = Math.max(1, Math.ceil(words / 220));

  return d;
}

// Create post
app.post("/api/admin/posts", async (req, res) => {
  try {
    const d = prepare(req.body);

    d.id = uid();
    d.author = d.author || req.member.name || "Entrepreneur Desk";
    d.author_id = req.member.user_id;
    d.slug = await uniqueSlug(
      col("posts"),
      d.slug || d.title
    );
    d.created_at = now();

    await col("posts").insertOne(d);

    res.status(201).json(safe(d));
  } catch (e) {
    console.error("POST CREATE ERROR:", e);

    res.status(e.status || 500).json({
      detail: e.message,
    });
  }
});

// UPDATE POST — FIXED MONGODB IMMUTABLE _id ERROR
app.put("/api/admin/posts/:id", async (req, res) => {
  try {
    const filter = {
      id: req.params.id,
      ...notDeleted,
      ...scope(req),
    };

    const old = await col("posts").findOne(filter);

    if (!old) {
      return res.status(404).json({
        detail: "Not found",
      });
    }

    const d = prepare(req.body, old);

    // IMPORTANT:
    // MongoDB does not allow changing its immutable _id field.
    // Also preserve the existing application-level id.
    delete d._id;
    delete d.id;

    // Generate unique slug
    d.slug = await uniqueSlug(
      col("posts"),
      d.slug || d.title,
      req.params.id
    );

    // Update only editable fields
    const result = await col("posts").updateOne(
      filter,
      {
        $set: d,
      }
    );

    if (!result.matchedCount) {
      return res.status(404).json({
        detail: "Post not found or access denied",
      });
    }

    const updated = await col("posts").findOne(
      filter,
      {
        projection: { _id: 0 },
      }
    );

    res.json(updated);
  } catch (e) {
    console.error("POST UPDATE ERROR:", e);

    res.status(e.status || 500).json({
      detail: e.message || "Could not update post",
    });
  }
});

// Delete post
app.delete("/api/admin/posts/:id", async (req, res) => {
  const r = await col("posts").updateOne(
    {
      id: req.params.id,
      ...notDeleted,
      ...scope(req),
    },
    {
      $set: {
        deleted: true,
        status: "draft",
        updated_at: now(),
      },
    }
  );

  if (!r.matchedCount) {
    return res.status(404).json({
      detail: "Not found",
    });
  }

  res.json({ ok: true });
});

// Admin categories
app.get("/api/admin/categories", async (req, res) => {
  const cats = await col("categories")
    .find({}, { projection: { _id: 0 } })
    .sort({ name: 1 })
    .toArray();

  const counts = await col("posts")
    .aggregate([
      { $match: notDeleted },
      {
        $group: {
          _id: "$category",
          n: { $sum: 1 },
        },
      },
    ])
    .toArray();

  const m = Object.fromEntries(
    counts.map((x) => [x._id, x.n])
  );

  res.json(
    cats.map((c) => ({
      ...c,
      post_count: m[c.name] || 0,
    }))
  );
});

app.post("/api/admin/categories", admin, async (req, res) => {
  const b = req.body;

  if (!b.name || b.name.trim().length < 2) {
    return res.status(422).json({
      detail: "Category name is required",
    });
  }

  if (
    await col("categories").findOne({
      name: new RegExp(`^${b.name.trim()}$`, "i"),
    })
  ) {
    return res.status(409).json({
      detail: "A category with this name already exists",
    });
  }

  const d = {
    id: uid(),
    name: b.name.trim(),
    slug: await uniqueSlug(col("categories"), b.slug || b.name),
    description: b.description || "",
    seo_title: b.seo_title || "",
    meta_description: b.meta_description || "",
    post_count: 0,
  };

  await col("categories").insertOne(d);

  res.status(201).json(d);
});

app.put("/api/admin/categories/:id", admin, async (req, res) => {
  const old = await col("categories").findOne({
    id: req.params.id,
  });

  if (!old) {
    return res.status(404).json({
      detail: "Not found",
    });
  }

  const b = req.body;

  const d = {
    name: b.name.trim(),
    slug: await uniqueSlug(
      col("categories"),
      b.slug || b.name,
      req.params.id
    ),
    description: b.description || "",
    seo_title: b.seo_title || "",
    meta_description: b.meta_description || "",
  };

  await col("categories").updateOne(
    { id: req.params.id },
    { $set: d }
  );

  if (old.name !== d.name) {
    await col("posts").updateMany(
      { category: old.name },
      { $set: { category: d.name } }
    );
  }

  res.json({
    ...safe(old),
    ...d,
  });
});

app.delete("/api/admin/categories/:id", admin, async (req, res) => {
  const c = await col("categories").findOne({
    id: req.params.id,
  });

  if (!c) {
    return res.status(404).json({
      detail: "Not found",
    });
  }

  const n = await col("posts").countDocuments({
    category: c.name,
    ...notDeleted,
  });

  if (n) {
    return res.status(409).json({
      detail: `${n} post(s) still use this category. Move them first.`,
    });
  }

  await col("categories").deleteOne({
    id: req.params.id,
  });

  res.json({ ok: true });
});

// Admin lists
app.get("/api/admin/lists", admin, async (req, res) => {
  const docs = await col("lists")
    .find(notDeleted, { projection: { _id: 0 } })
    .sort({ updated_at: -1 })
    .toArray();

  res.json(
    docs.map((d) => ({
      id: d.id,
      slug: d.slug,
      title: d.title,
      year: d.year,
      description: d.description || "",
      count: d.entries?.length || 0,
      status: d.status || "published",
    }))
  );
});

app.get("/api/admin/lists/:id", admin, async (req, res) => {
  const d = await col("lists").findOne(
    {
      id: req.params.id,
      ...notDeleted,
    },
    {
      projection: { _id: 0 },
    }
  );

  if (!d) {
    return res.status(404).json({
      detail: "Not found",
    });
  }

  res.json(d);
});

app.post("/api/admin/lists", admin, async (req, res) => {
  const b = req.body;

  const d = {
    ...b,
    id: uid(),
    slug: await uniqueSlug(col("lists"), b.slug || b.title),
    entries: (b.entries || []).map((x, i) => ({
      ...x,
      rank: i + 1,
    })),
    updated_at: now(),
  };

  await col("lists").insertOne(d);

  res.status(201).json(d);
});

app.put("/api/admin/lists/:id", admin, async (req, res) => {
  const b = req.body;

  const d = {
    ...b,
    slug: await uniqueSlug(
      col("lists"),
      b.slug || b.title,
      req.params.id
    ),
    entries: (b.entries || []).map((x, i) => ({
      ...x,
      rank: i + 1,
    })),
    updated_at: now(),
  };

  // Prevent immutable MongoDB field update here too.
  delete d._id;
  delete d.id;

  const r = await col("lists").updateOne(
    {
      id: req.params.id,
      ...notDeleted,
    },
    {
      $set: d,
    }
  );

  if (!r.matchedCount) {
    return res.status(404).json({
      detail: "Not found",
    });
  }

  res.json(
    await col("lists").findOne(
      { id: req.params.id },
      { projection: { _id: 0 } }
    )
  );
});

app.delete("/api/admin/lists/:id", admin, async (req, res) => {
  const d = await col("lists").findOne({
    id: req.params.id,
    ...notDeleted,
  });

  if (!d) {
    return res.status(404).json({
      detail: "Not found",
    });
  }

  await col("lists").updateOne(
    { id: req.params.id },
    {
      $set: {
        deleted: true,
        status: "draft",
        slug: `${d.slug}-deleted-${req.params.id.slice(0, 8)}`,
      },
    }
  );

  res.json({ ok: true });
});

// Reindex
app.post("/api/admin/posts/:id/reindex", async (req, res) => {
  const p = await col("posts").findOne({
    id: req.params.id,
    ...notDeleted,
    ...scope(req),
  });

  if (!p) {
    return res.status(404).json({
      detail: "Published post not found",
    });
  }

  const indexing = [
    {
      provider: "manual",
      enabled: false,
      ok: false,
      message: "Indexing provider is not configured",
      at: now().toISOString(),
    },
  ];

  await col("posts").updateOne(
    { id: p.id },
    {
      $set: { indexing },
    }
  );

  res.json({
    ...safe(p),
    indexing,
  });
});

// CSV helper
function csvResponse(res, rows, cols, filename) {
  const esc = (v) =>
    '"' +
    String(v ?? "").replaceAll('"', '""') +
    '"';

  const body =
    "\ufeff" +
    [
      cols.map(esc).join(","),
      ...rows.map((r) =>
        cols
          .map((c) =>
            esc(r[c] instanceof Date ? r[c].toISOString() : r[c])
          )
          .join(",")
      ),
    ].join("\r\n");

  res
    .set("Content-Type", "text/csv; charset=utf-8")
    .set("Content-Disposition", `attachment; filename="${filename}"`)
    .send(body);
}

// Downloads
app.get("/api/admin/nominations.csv", admin, async (req, res) => {
  csvResponse(
    res,
    await col("nominations").find({}).toArray(),
    [
      "created_at",
      "full_name",
      "email",
      "company",
      "role",
      "website",
      "industry",
      "pitch",
    ],
    "get-featured-submissions.csv"
  );
});

app.get("/api/admin/subscribers.csv", admin, async (req, res) => {
  csvResponse(
    res,
    await col("newsletter").find({}).toArray(),
    ["email", "created_at"],
    "newsletter-subscribers.csv"
  );
});

// Admin settings
app.put("/api/admin/settings", admin, async (req, res) => {
  const d = {
    ...req.body,
    id: "site",
    site_url: String(req.body.site_url || "")
      .trim()
      .replace(/\/$/, ""),
  };

  delete d._id;

  await col("settings").updateOne(
    { id: "site" },
    { $set: d },
    { upsert: true }
  );

  res.json(d);
});

// Admin nominations
app.get("/api/admin/nominations", admin, async (req, res) => {
  res.json(
    await col("nominations")
      .find({}, { projection: { _id: 0 } })
      .sort({ created_at: -1 })
      .limit(5000)
      .toArray()
  );
});

// Admin subscribers
app.get("/api/admin/subscribers", admin, async (req, res) => {
  res.json(
    await col("newsletter")
      .find({}, { projection: { _id: 0 } })
      .sort({ created_at: -1 })
      .limit(50000)
      .toArray()
  );
});

// Admin users
app.get("/api/admin/users", admin, async (req, res) => {
  res.json({
    roles: ["admin", "author", "pending"],
    users: await col("users")
      .find(
        {},
        {
          projection: {
            _id: 0,
            user_id: 1,
            email: 1,
            name: 1,
            role: 1,
          },
        }
      )
      .sort({ created_at: -1 })
      .toArray(),
  });
});

app.patch("/api/admin/users/:user_id/role", admin, async (req, res) => {
  if (!["admin", "author", "pending"].includes(req.body.role)) {
    return res.status(422).json({
      detail: "Invalid role",
    });
  }

  const target = await col("users").findOne({
    user_id: req.params.user_id,
  });

  if (!target) {
    return res.status(404).json({
      detail: "Not found",
    });
  }

  if (
    target.role === "admin" &&
    req.body.role !== "admin" &&
    (await col("users").countDocuments({ role: "admin" })) <= 1
  ) {
    return res.status(409).json({
      detail: "Keep at least one admin",
    });
  }

  await col("users").updateOne(
    { user_id: req.params.user_id },
    {
      $set: { role: req.body.role },
    }
  );

  res.json({
    user_id: req.params.user_id,
    role: req.body.role,
  });
});

// Author invites
app.get("/api/admin/invites", admin, async (req, res) => {
  res.json(
    await col("author_invites")
      .find({}, { projection: { _id: 0, email: 1 } })
      .toArray()
  );
});

app.post("/api/admin/invites", admin, async (req, res) => {
  const email = String(req.body.email || "").toLowerCase();

  await col("author_invites").updateOne(
    { email },
    {
      $setOnInsert: {
        email,
        created_at: now(),
      },
    },
    {
      upsert: true,
    }
  );

  await col("users").updateMany(
    {
      email,
      role: "pending",
    },
    {
      $set: { role: "author" },
    }
  );

  res.json({ email });
});

app.delete("/api/admin/invites/:email", admin, async (req, res) => {
  await col("author_invites").deleteOne({
    email: req.params.email.toLowerCase(),
  });

  res.json({ ok: true });
});

// Media upload
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    cb(
      null,
      /^image\/(jpeg|png|webp|gif|svg\+xml|x-icon|vnd.microsoft.icon)$/.test(
        file.mimetype
      )
    );
  },
});

app.get("/api/admin/media", async (req, res) => {
  const media = await col("media")
    .find(
      { is_deleted: false },
      {
        projection: {
          _id: 0,
          data: 0,
        },
      }
    )
    .sort({ created_at: -1 })
    .toArray();

  res.json(
    media.map((item) => ({
      ...item,
      url: `/api/media/${item.id}`,
    }))
  );
});

app.post(
  "/api/admin/media",
  upload.single("file"),
  async (req, res) => {
    if (!req.file) {
      return res.status(415).json({
        detail: "Valid image file required",
      });
    }

    const id = uid();

    const doc = {
      id,
      filename: req.file.originalname,
      content_type: req.file.mimetype,
      size: req.file.size,
      alt: req.file.originalname
        .replace(/\.[^.]+$/, "")
        .replace(/[-_]/g, " "),
      uploaded_by: req.member.user_id,
      uploaded_by_name: req.member.name || "",
      is_deleted: false,
      created_at: now(),
      storage_path: `media/${id}`,
    };

    await col("media").insertOne({
      ...doc,
      data: req.file.buffer,
    });

    res.status(201).json({
      ...doc,
      url: `/api/media/${id}`,
    });
  }
);

// Serve media
app.get("/api/media/:id", async (req, res) => {
  const d = await col("media").findOne({
    id: req.params.id,
    is_deleted: false,
  });

  if (!d?.data) {
    return res.status(404).json({
      detail: "File not found",
    });
  }

  res
    .set("Content-Type", d.content_type)
    .set("Cache-Control", "public,max-age=31536000,immutable")
    .send(d.data.buffer || d.data);
});

// Update media alt text
app.patch("/api/admin/media/:id", async (req, res) => {
  const r = await col("media").updateOne(
    {
      id: req.params.id,
      is_deleted: false,
      ...(req.member.role === "admin"
        ? {}
        : { uploaded_by: req.member.user_id }),
    },
    {
      $set: {
        alt: req.body.alt || "",
      },
    }
  );

  if (!r.matchedCount) {
    return res.status(404).json({
      detail: "Not found",
    });
  }

  const d = await col("media").findOne(
    { id: req.params.id },
    {
      projection: {
        _id: 0,
        data: 0,
      },
    }
  );

  res.json({
    ...d,
    url: `/api/media/${d.id}`,
  });
});

// Delete media
app.delete("/api/admin/media/:id", async (req, res) => {
  const r = await col("media").updateOne(
    {
      id: req.params.id,
      is_deleted: false,
      ...(req.member.role === "admin"
        ? {}
        : { uploaded_by: req.member.user_id }),
    },
    {
      $set: {
        is_deleted: true,
      },
    }
  );

  if (!r.matchedCount) {
    return res.status(404).json({
      detail: "Not found",
    });
  }

  res.json({ ok: true });
});

// Sitemap
app.get("/api/sitemap.xml", async (req, res) => {
  const base =
    process.env.SITE_URL ||
    `${req.protocol}://${req.get("host")}`;

  const posts = await col("posts")
    .find(
      {
        ...live,
        noindex: { $ne: true },
      },
      {
        projection: {
          slug: 1,
          updated_at: 1,
        },
      }
    )
    .toArray();

  const urls = [
    `${base}/`,
    `${base}/stories`,
    `${base}/lists`,
    `${base}/news`,
  ];

  const xml =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
    [
      ...urls,
      ...posts.map((p) => `${base}/story/${p.slug}`),
    ]
      .map((u) => `<url><loc>${u}</loc></url>`)
      .join("") +
    `</urlset>`;

  res.type("application/xml").send(xml);
});

// Robots
app.get("/api/robots.txt", async (req, res) => {
  const base =
    process.env.SITE_URL ||
    `${req.protocol}://${req.get("host")}`;

  const s = (await col("settings").findOne({ id: "site" })) || {};

  res.type("text/plain").send(
    `User-agent: *\n` +
      `Allow: /\n` +
      `Disallow: /admin\n` +
      `Disallow: /sign-in\n` +
      `Disallow: /sign-up\n` +
      `${s.robots_extra || ""}\n` +
      `Sitemap: ${base}/api/sitemap.xml\n`
  );
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err);

  res.status(err.status || 500).json({
    detail: err.message || "Internal server error",
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Entrepreneur Desk API running on port ${PORT}`);
});