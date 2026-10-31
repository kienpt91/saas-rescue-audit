import Stripe from "stripe";
import { NextResponse } from "next/server";
import { requireUser } from "@/lib/auth";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

// the client sends a plan key; only these keys map to a price
const PRICES: Record<string, string | undefined> = {
  pro: process.env.STRIPE_PRICE_PRO,
  team: process.env.STRIPE_PRICE_TEAM,
};

export async function POST(request: Request) {
  const session = await requireUser();
  if (!session) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const body: unknown = await request.json();
  const plan = typeof body === "object" && body !== null && "plan" in body && typeof body.plan === "string" ? body.plan : "";
  const price = Object.hasOwn(PRICES, plan) ? PRICES[plan] : undefined;
  if (!price) return NextResponse.json({ error: "unknown plan" }, { status: 400 });

  const { data: profile } = await session.db
    .from("profiles")
    .select("stripe_customer_id")
    .eq("id", session.user.id)
    .single();

  const checkout = await stripe.checkout.sessions.create({
    mode: "subscription",
    customer: profile?.stripe_customer_id ?? undefined,
    client_reference_id: session.user.id,
    line_items: [{ price, quantity: 1 }],
    success_url: `${process.env.SITE_URL}/dashboard?paid=1`,
    cancel_url: `${process.env.SITE_URL}/dashboard`,
  });

  return NextResponse.json({ url: checkout.url });
}
