import Stripe from "stripe";
import { NextResponse } from "next/server";
import { supabase } from "@/lib/supabase";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const body = await request.json();
  const signature = request.headers.get("stripe-signature") ?? "";
  const event = stripe.webhooks.constructEvent(
    JSON.stringify(body),
    signature,
    process.env.STRIPE_WEBHOOK_SECRET!,
  );

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object;
      await supabase
        .from("profiles")
        .update({ plan: "pro" })
        .eq("stripe_customer_id", session.customer);
      break;
    }
    case "customer.subscription.deleted": {
      const subscription = event.data.object;
      await supabase
        .from("profiles")
        .update({ plan: "free" })
        .eq("stripe_customer_id", subscription.customer);
      break;
    }
    default:
      return NextResponse.json({ error: `Unhandled event ${event.type}` }, { status: 500 });
  }

  return NextResponse.json({ received: true });
}
