import Stripe from "stripe";
import { NextResponse } from "next/server";
import { rateLimit } from "@/lib/rate-limit";
import { admin } from "@/lib/supabase-admin";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const ip = request.headers.get("x-forwarded-for") ?? "unknown";
  if (!rateLimit(`stripe-webhook:${ip}`, 300, 60_000)) {
    return NextResponse.json({ error: "rate limited" }, { status: 429 });
  }

  // the signature covers the raw bytes, so read the body as text and parse nothing yet
  const rawBody = await request.text();
  const signature = request.headers.get("stripe-signature");
  if (!signature) return NextResponse.json({ error: "missing signature" }, { status: 400 });

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    return NextResponse.json({ error: "invalid signature" }, { status: 400 });
  }

  // claim the event id first; a repeated delivery hits the primary key and is acknowledged
  const claim = await admin.from("stripe_events").insert({ id: event.id });
  if (claim.error?.code === "23505") return NextResponse.json({ received: true, duplicate: true });
  if (claim.error) return NextResponse.json({ error: "could not record event" }, { status: 500 });

  switch (event.type) {
    case "checkout.session.completed": {
      const checkout = event.data.object;
      if (typeof checkout.customer === "string") {
        await admin.from("profiles").update({ plan: "pro" }).eq("stripe_customer_id", checkout.customer);
      }
      break;
    }
    case "customer.subscription.deleted": {
      const subscription = event.data.object;
      if (typeof subscription.customer === "string") {
        await admin.from("profiles").update({ plan: "free" }).eq("stripe_customer_id", subscription.customer);
      }
      break;
    }
    default:
      // event types this endpoint does not handle are acknowledged so Stripe does not retry them
      break;
  }

  return NextResponse.json({ received: true });
}
