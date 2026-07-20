import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, btcpay-sig",
}

const BTCPAY_URL = 'https://btcpay805858.lndyn.com'
const BTCPAY_STORE_ID = '4c25ngaLGLQ77x5rpRGZkYFGGh16j6VgZf1Ctwe9ffHw'

serve(async (req: Request) => {
  if (req.method === "OPTIONS") { return new Response("ok", { headers: corsHeaders }) }

  try {
    const rawBody = await req.text()
    if (!rawBody || rawBody.trim() === "") {
      return new Response(JSON.stringify({ received: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } })
    }
    const payload = JSON.parse(rawBody)

    const supabaseUrl = Deno.env.get('SUPABASE_URL') || ''
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || Deno.env.get('SUPABASE_ANON_KEY') || ''
    const supabase = createClient(supabaseUrl, supabaseKey)

    // 1. STATUS CHECK
    if (payload.checkStatus && payload.invoiceId) {
      const { data } = await supabase.from('payments').select('status').eq('invoice_id', payload.invoiceId).single()
      return new Response(JSON.stringify({ status: data?.status || 'pending' }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } })
    }

    // 2. CREATE INVOICE
    if (payload.amount && payload.source && !payload.type) {
      const amount = parseFloat(payload.amount)
      const source = payload.source
      const email = payload.email || ''
      const paymentType = payload.paymentType || 'lightning'
      const cfCity = req.headers.get('CF-IPCity') || payload.city || ''
      const cfCountry = req.headers.get('CF-IPCountry') || payload.country || ''

      // 🟢 DYNAMIC DOMAIN FIX: ফ্রন্টএন্ড থেকে আসা ডাইনামিক সোর্স নেবে 🟢
      const requestOrigin = req.headers.get("origin") || payload.source;

      if (!amount || amount < 2) {
        return new Response(JSON.stringify({ error: 'Minimum amount is $2' }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } })
      }

      const btcpayApiKey = Deno.env.get('BTCPAY_API_KEY') ?? ''
      if (!btcpayApiKey) {
        return new Response(JSON.stringify({ error: 'BTCPay API key not configured' }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } })
      }

      let paymentMethods: string[]
      if (paymentType === 'lightning' || paymentType === 'usdc') { paymentMethods = ['BTC-LN', 'BTC-LightningNetwork'] } 
      else if (paymentType === 'onchain') { paymentMethods = ['BTC-CHAIN', 'BTC'] } 
      else { paymentMethods = ['BTC-LN', 'BTC-LightningNetwork', 'BTC-CHAIN', 'BTC'] }

      const invoiceRes = await fetch(`${BTCPAY_URL}/api/v1/stores/${BTCPAY_STORE_ID}/invoices`, {
        method: 'POST',
        headers: { 'Authorization': `token ${btcpayApiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount: amount.toString(), currency: 'USD', orderId: `order-${Date.now()}`, buyerEmail: email || undefined, notificationUrl: `${Deno.env.get('SUPABASE_URL')}/functions/v1/btcpay-webhook`, redirectUrl: requestOrigin, checkout: { paymentMethods, expirationMinutes: 60 } })
      })

      if (!invoiceRes.ok) { return new Response(JSON.stringify({ error: 'Failed to create invoice' }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }) }

      const invoiceData = await invoiceRes.json()
      const invoiceId = invoiceData.id
      let lightningCode = '', btcAddress = '', btcDue = 0

      try {
        const pmRes = await fetch(`${BTCPAY_URL}/api/v1/stores/${BTCPAY_STORE_ID}/invoices/${invoiceId}/payment-methods`, { headers: { 'Authorization': `token ${btcpayApiKey}` } })
        if (pmRes.ok) {
          const pmData = await pmRes.json()
          for (const pm of pmData) {
            const dest = (pm.destination || '').trim()
            if (dest.startsWith('lnbc') || dest.startsWith('lntb')) { lightningCode = dest; btcDue = parseFloat(pm.due || pm.amount || '0') } 
            else if (dest.length >= 26 && dest.length <= 62) { btcAddress = dest; if (!btcDue) btcDue = parseFloat(pm.due || pm.amount || '0') }
          }
        }
      } catch (pmErr) { console.error('[PM error]', pmErr) }

      // 🟢 PENDING STATUS FIX 🟢
      const { error: dbErr } = await supabase.from('payments').insert({
        invoice_id: invoiceId, amount, currency: 'USD', status: 'pending', payment_type: paymentType, source, email, city: cfCity, country: cfCountry
      })

      if (dbErr) { return new Response(JSON.stringify({ error: 'Failed to save payment' }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }) }

      return new Response(JSON.stringify({ invoiceId, amount, paymentType, lightningCode, btcAddress, btcAmount: btcDue, checkoutLink: invoiceData.checkoutLink }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } })
    }

    // 3. BTCPAY WEBHOOK
    if (payload.type) {
      const webhookSecret = Deno.env.get('BTCPAY_WEBHOOK_SECRET')

      if (webhookSecret) {
        const sigHeader = req.headers.get('btcpay-sig')
        if (!sigHeader || !sigHeader.startsWith('sha256=')) { return new Response(JSON.stringify({ error: 'Unauthorized webhook' }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }) }
        const encoder = new TextEncoder()
        const signKey = await crypto.subtle.importKey("raw", encoder.encode(webhookSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
        const macBuffer = await crypto.subtle.sign("HMAC", signKey, encoder.encode(rawBody))
        const macHex = Array.from(new Uint8Array(macBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')
        if (`sha256=${macHex}` !== sigHeader) { return new Response(JSON.stringify({ error: 'Invalid webhook signature' }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }) }
      }

      if (payload.type === 'InvoiceSettled' || payload.type === 'InvoicePaymentSettled') {
        const invoiceId = payload.invoiceId
        const { data: existing } = await supabase.from('payments').select('id').eq('invoice_id', invoiceId).single()

        if (existing) { await supabase.from('payments').update({ status: 'settled', paid_at: new Date().toISOString() }).eq('invoice_id', invoiceId) } 
        else { await supabase.from('payments').insert({ invoice_id: invoiceId, amount: payload.payment?.value || 0, currency: 'USD', status: 'settled', payment_type: payload.payment?.paymentMethodId?.includes('LN') ? 'lightning' : 'onchain', source: 'webhook', paid_at: new Date().toISOString() }) }
      }

      if (payload.type === 'InvoiceExpired') {
        await supabase.from('payments').update({ status: 'expired' }).eq('invoice_id', payload.invoiceId).in('status', ['new', 'pending'])
      }

      return new Response(JSON.stringify({ received: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } })
    }

    return new Response(JSON.stringify({ received: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } })
  } catch (err) {
    return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } })
  }
})
