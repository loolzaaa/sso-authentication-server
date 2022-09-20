function getFingerprint() {
    return new Promise((resolve, reject) => {
        async function getHash () {
            const options = {
                excludes: {
                    plugins: true,
                    localStorage: true,
                    adBlock: true,
                    screenResolution: true,
                    availableScreenResolution: true,
                    enumerateDevices: true,
                    pixelRatio: true,
                    doNotTrack: true
                }
            }

            try {
                const components = await Fingerprint2.getPromise(options);
                const values = components.map(component => component.value);
                return String(Fingerprint2.x64hash128(values.join(''), 31));
            } catch (e) {
                reject(e);
            }
        }

        if (window.requestIdleCallback) {
            requestIdleCallback(async () => resolve(await getHash()));
        } else {
            setTimeout(async () => resolve(await getHash()), 500);
        }
    });
}