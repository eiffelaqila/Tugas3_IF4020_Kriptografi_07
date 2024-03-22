import React, { useState } from "react";
import axios from "axios";
import { FaLock, FaUnlock, FaDownload } from "react-icons/fa"

function App() {
  const backendUrl = process.env.REACT_APP_BACKEND_URL;
  const [data, setData] = useState({
    cipherMode: "ecb",
    keySize: 128,
  })
  const [cipherType, setCipherType] = useState('');

  const [isLoading, setLoading] = useState(false);
  const [result, setResult] = useState(undefined);
  const [fileResult, setFileResult] = useState(undefined);
  const [error, setError] = useState(undefined);

  const mapDataToAxiosValue = (d) => {
    const data = {};
    if (d.inputType === "text") {
      data.inputText = d.inputText;
    }

    if (["cbc", "ofb", "cfb"].includes(d.cipherMode)) {
      data.iv = d.iv;
    } else if (d.cipherMode === "counter") {
      data.counter = d.counter;
    }

    data.keySize = d.keySize;
    data.key = d.key;
    
    return data;
  }

  const handleDownloadResult = (e) => {
    const url = URL.createObjectURL(fileResult);

    const a = document.createElement("a");
    a.href = url;
    a.download = fileResult.name;

    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    URL.revokeObjectURL(url);
  }

  const handleChange = (e) => {
    let newData = {...data};
    newData[e.target.id] = e.target.value;
    setData(newData);
  }

  const handleChangeFile = (e) => {
    let newData = {...data};
    newData.file = e.target.files[0];
    setData(newData);
  }

  const isKeyValid = (key, keySize) => key.length === keySize/8;

  const handleSubmit = async (e) => {
    e.preventDefault();

    const mappedData = mapDataToAxiosValue(data);
    const cipherType = e.nativeEvent.submitter.value;
    setCipherType(cipherType);

    if (!isKeyValid(mappedData.key, mappedData.keySize)) {
      setError(`Key should be ${mappedData.keySize/8} characters long`);
      return;
    }

    setResult(undefined);
    setFileResult(undefined);
    setLoading(true);
    
    try {
      if (data.inputType === "text") {
        const response = await axios.post(
          `${backendUrl}/${data.cipherMode}/${cipherType}`,
          mappedData
        )

        const fileResponse = new File(
          [response.data],
          "result",
          {
            type: 'text/plain',
          },
        )

        setLoading(false);
        setError(undefined);
        setResult({
          text: response.data,
          base64: btoa(response.data),
        });
        setFileResult(fileResponse);
      } else {
        const file = data.file;
        const formData = new FormData();
        formData.append("file", file);

        const response = await axios.post(
          `${backendUrl}/${data.cipherMode}/${cipherType}-file`,
          formData,
          {
            params: { ...mappedData },
            responseType: 'arraybuffer'
          },
        );

        const binaryData = new Uint8Array(response.data);

        const fileResponse = new File(
          [binaryData],
          file ? `${cipherType}ed-${data.cipherMode}-${file.name}` : `${cipherType}ed-result`,
          {
            type: file ? file.type : 'text/plain',
          },
        )

        setLoading(false);
        setError(undefined);
        setResult({
          base64: "Too large to display.",
        });
        setFileResult(fileResponse);
      }
    } catch (e) {
      setLoading(false);
      if (e.request.status === 400) {
        setError(e.response.data.error);
      } else {
        setError(e.message);
      }
    }
  }

  const isType = (type) => data.inputType === type;
  const isCipherMode = (fun) => data.cipherMode === fun;

  return (
    <div className="relative flex flex-col justify-center min-h-screen bg-white">
      <div className="w-full px-6 py-10 m-auto lg:max-w-xl">
        <h1 className="text-3xl font-bold text-gray-700">Tugas 3 IF4020 - Kriptografi</h1>
        <h3 className="pt-2 font-medium leading-normal text-gray-500 text-md">
          Oleh:
          <br />
          - 13520074 - Eiffel Aqila Amarendra
          <br />
          - 13520122 - Alifia Rahmah
          <br />
          - 13520125 - Ikmal Alfaozi
        </h3>
        <div className="w-full py-2 my-4">
          <form onSubmit={(e) => handleSubmit(e)} className="flex flex-col gap-2 mt-6">
            <div>
              <label htmlFor="inputType">Input Type</label>
              <select id="inputType" defaultValue="text" onChange={(e) => handleChange(e)}>
                <option value="text">Text</option>
                <option value="file">File</option>
              </select>
            </div>
            <div className={isType("text") ? "" : "hidden"}>
              <label htmlFor="inputText">Plaintext / Ciphertext</label>
              <input type="text" id="inputText" placeholder="Enter text" onChange={(e) => handleChange(e)} required={data.inputType === "text"} />
            </div>
            <div className={isType("file") ? "" : "hidden"}>
              <label htmlFor="file">File</label>
              <input type="file" id="file" placeholder="Enter file" onChange={(e) => handleChangeFile(e)} required={data.inputType === "file"} />
            </div>
            <div>
              <label htmlFor="cipherMode">Cipher Mode</label>
              <select id="cipherMode" defaultValue="ecb" onChange={(e) => handleChange(e)}>
                <option value="ecb">ECB</option>
                <option value="cbc">CBC</option>
                <option value="ofb">OFB</option>
                <option value="cfb">CFB</option>
                <option value="counter">Counter</option>
              </select>
            </div>
            <div>
              <label htmlFor="keySize">Key Size</label>
              <select id="keySize" defaultValue={128} onChange={(e) => handleChange(e)}>
                <option value={128}>128</option>
                <option value={192}>192</option>
                <option value={256}>256</option>
              </select>
            </div>
            <div>
              <label htmlFor="key">Key</label>
              <input type="text" id="key" placeholder="Enter key" onChange={(e) => handleChange(e)} required />
            </div>
            <div className={!isCipherMode('ecb') && !isCipherMode('counter') ? "" : "hidden"}>
              <label htmlFor="iv">Initialization Vector (Should be 128 bit/16 characters)</label>
              <input type="text" id="iv" placeholder="Enter initialization vector" onChange={(e) => handleChange(e)} required={!['ecb', 'counter'].includes(data.cipherMode)} />
            </div>
            <div className={isCipherMode('counter') ? "" : "hidden"}>
              <label htmlFor="counter">Counter</label>
              <input type="text" id="counter" placeholder="Enter counter" onChange={(e) => handleChange(e)} required={data.cipherMode === 'counter'} />
            </div>
            <div className="flex gap-2 mt-6">
              <button type="submit" value="encrypt" className="bg-indigo-700 hover:bg-indigo-600 focus:bg-indigo-600">
                <FaLock /> Encrypt
              </button>
              <button type="submit" value="decrypt" className="bg-orange-700 hover:bg-orange-600 focus:bg-orange-600">
                <FaUnlock /> Decrypt
              </button>
            </div>
          </form>
        </div>
        <hr className="h-px my-8 bg-gray-700 border-0" />
        <div className={`items-center justify-center w-full ${isLoading ? "flex" : "hidden"}`}>
            <svg aria-hidden="true" className="w-8 h-8 text-gray-200 animate-spin fill-indigo-600" viewBox="0 0 100 101" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M100 50.5908C100 78.2051 77.6142 100.591 50 100.591C22.3858 100.591 0 78.2051 0 50.5908C0 22.9766 22.3858 0.59082 50 0.59082C77.6142 0.59082 100 22.9766 100 50.5908ZM9.08144 50.5908C9.08144 73.1895 27.4013 91.5094 50 91.5094C72.5987 91.5094 90.9186 73.1895 90.9186 50.5908C90.9186 27.9921 72.5987 9.67226 50 9.67226C27.4013 9.67226 9.08144 27.9921 9.08144 50.5908Z" fill="#e5e7eb"/>
                <path d="M93.9676 39.0409C96.393 38.4038 97.8624 35.9116 97.0079 33.5539C95.2932 28.8227 92.871 24.3692 89.8167 20.348C85.8452 15.1192 80.8826 10.7238 75.2124 7.41289C69.5422 4.10194 63.2754 1.94025 56.7698 1.05124C51.7666 0.367541 46.6976 0.446843 41.7345 1.27873C39.2613 1.69328 37.813 4.19778 38.4501 6.62326C39.0873 9.04874 41.5694 10.4717 44.0505 10.1071C47.8511 9.54855 51.7191 9.52689 55.5402 10.0491C60.8642 10.7766 65.9928 12.5457 70.6331 15.2552C75.2735 17.9648 79.3347 21.5619 82.5849 25.841C84.9175 28.9121 86.7997 32.2913 88.1811 35.8758C89.083 38.2158 91.5421 39.6781 93.9676 39.0409Z" fill="currentFill"/>
            </svg>
            <span className="sr-only">Loading...</span>
        </div>
        {error && (
          <div className="w-full py-2 my-4">
            <div className="w-full p-4 mt-4 bg-red-100 border border-red-600 rounded-md">
              <p className="text-xl font-semibold text-red-600">{JSON.stringify(error)}</p>
            </div>
          </div>
        )}
        {result && (
          <div className="w-full py-2 my-4">
            <h2 className="text-xl font-bold text-gray-700">{cipherType === 'encrypt' ? 'Encrypted' : 'Decrypted'} Text</h2>
            <div className="w-full my-4">
              <div className={`w-full my-4 ${result.text ? "block" : "hidden"}`}>
                <h5 className="text-sm font-semibold text-gray-800">Text Result</h5>
                <div className="w-full p-4 overflow-x-scroll border border-gray-300 rounded-md max-h-lg bg-gray-50">
                  <p className="text-base font-medium text-gray-800">{result.text}</p>
                </div>
              </div>
            </div>
            <button type="button" onClick={(e) => handleDownloadResult(e)} className="bg-indigo-700 hover:bg-indigo-600 focus:bg-indigo-600">
              <FaDownload /> Download File
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
