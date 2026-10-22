(() => {
  const button = document.getElementById('push-toggle');
  const status = document.getElementById('push-status');

  if (!button || !status) {
    return;
  }

  const setStatus = (message, isError = false) => {
    status.textContent = message;
    status.classList.toggle('push-status-error', isError);
  };

  const applicationServerKey = (base64Key) => {
    const padding = '='.repeat((4 - (base64Key.length % 4)) % 4);
    const base64 = (base64Key + padding).replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
  };

  const saveSubscription = async (url, subscription) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': button.dataset.csrfToken,
      },
      body: JSON.stringify(subscription),
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || 'Tidak dapat menyimpan pengaturan notifikasi.');
    }
    return result;
  };

  const updateButton = (enabled) => {
    button.setAttribute('aria-pressed', String(enabled));
    button.textContent = enabled ? 'Matikan notifikasi' : 'Aktifkan notifikasi';
  };

  const getRegistration = () => navigator.serviceWorker.register('/service-worker.js');

  const syncExistingSubscription = async () => {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      setStatus('Browser ini belum mendukung notifikasi push.', true);
      button.disabled = true;
      return;
    }
    if (Notification.permission === 'denied') {
      setStatus('Izin notifikasi diblokir di pengaturan browser.', true);
      return;
    }
    if (Notification.permission !== 'granted') {
      return;
    }

    const registration = await getRegistration();
    const subscription = await registration.pushManager.getSubscription();
    if (subscription) {
      await saveSubscription('/push/subscribe', subscription.toJSON());
      updateButton(true);
      setStatus('Notifikasi aktif pada perangkat ini.');
    }
  };

  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      const registration = await getRegistration();
      const existing = await registration.pushManager.getSubscription();
      if (existing) {
        await saveSubscription('/push/unsubscribe', { endpoint: existing.endpoint });
        await existing.unsubscribe();
        updateButton(false);
        setStatus('Notifikasi dinonaktifkan pada perangkat ini.');
      } else {
        const permission = await Notification.requestPermission();
        if (permission !== 'granted') {
          setStatus('Izin notifikasi tidak diberikan.', true);
          return;
        }
        const subscription = await registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: applicationServerKey(button.dataset.publicKey),
        });
        await saveSubscription('/push/subscribe', subscription.toJSON());
        updateButton(true);
        setStatus('Notifikasi aktif pada perangkat ini.');
      }
    } catch (error) {
      setStatus(error.message || 'Gagal mengatur notifikasi.', true);
    } finally {
      button.disabled = false;
    }
  });

  syncExistingSubscription().catch((error) => {
    setStatus(error.message || 'Tidak dapat memeriksa pengaturan notifikasi.', true);
  });
})();
