if (window.u2f) { window.u2f_status.innerText = 'Register your device now!' }
else { window.u2f_status.innerText = 'No u2f library.' }
window.u2f.sign(appId, challenge, registeredKeys, function (response) {
    console.log(response);
    if (response.errorCode) {
        window.u2f_status.innerText = "Failed with error.";
    } else {
        window.u2f_status.innerText = "Registration recieved; just verifying now."
        window.data.value = JSON.stringify(response)
        window.setTimeout(function () { window.u2f_data.submit() }, 1);

        // window.fetch(
        //     '/register2',
        //     {
        //         'method': 'POST',
        //         'body': JSON.stringify(response),
        //         'headers': {'content-type': 'application/json'},
        //         'redirect': 'follow',
        //     }
        // ).then(function (resp) {
        //     console.log(resp);
        //     if (resp.ok) {
        //         window.u2f_status.innerText = "Registration Completed"
        //     } else {
        //         window.u2f_status.innerText = "Registration errored!"
        //     }
        // }).catch(function (err) {
        //     window.u2f_status.innerText = "Registration errored!"
        // })
    }
});
