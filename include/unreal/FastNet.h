// FastNet Network Library - Unreal Engine Integration
// 
// This header provides a C++ wrapper around the FastNet C API for use in 
// Unreal Engine projects. It handles memory management automatically
// and provides a more idiomatic C++ interface.
//
// SETUP:
// 1. Copy libfastnet.so (Linux), fastnet.dll (Windows), or libfastnet.dylib (macOS) 
//    to your project's Binaries folder
// 2. Copy this header and fastnet.h to your Source folder
// 3. Add the library to your Build.cs:
//    PublicAdditionalLibraries.Add(Path.Combine(ModuleDirectory, "libfastnet.so"));
//
// USAGE:
// ```cpp
// #include "FastNet.h"
//
// // In your GameInstance or NetworkManager:
// TUniquePtr<FFastNetClient> Client = MakeUnique<FFastNetClient>();
// if (Client->Connect("127.0.0.1", 7778)) {
//     // Connected!
// }
//
// // In Tick:
// FFastNetEvent Event;
// while (Client->Poll(Event)) {
//     switch (Event.Type) {
//         case EFastNetEventType::Data:
//             ProcessPacket(Event.Data, Event.DataLen);
//             break;
//     }
// }
//
// // Send data:
// TArray<uint8> Data = {...};
// Client->Send(0, Data);
// ```

#pragma once

#include "CoreMinimal.h"
#include "../fastnet.h"

/**
 * Event type enum for Unreal
 */
UENUM(BlueprintType)
enum class EFastNetEventType : uint8
{
    None = 0        UMETA(DisplayName = "None"),
    Connected = 1   UMETA(DisplayName = "Connected"),
    Data = 2        UMETA(DisplayName = "Data"),
    Disconnected = 3 UMETA(DisplayName = "Disconnected"),
    Error = 4       UMETA(DisplayName = "Error")
};

/**
 * Network event structure for Unreal
 */
USTRUCT(BlueprintType)
struct FFastNetEvent
{
    GENERATED_BODY()
    
    UPROPERTY(BlueprintReadOnly)
    EFastNetEventType Type = EFastNetEventType::None;
    
    UPROPERTY(BlueprintReadOnly)
    int32 PeerId = 0;
    
    UPROPERTY(BlueprintReadOnly)
    uint8 Channel = 0;
    
    UPROPERTY(BlueprintReadOnly)
    TArray<uint8> Data;
    
    UPROPERTY(BlueprintReadOnly)
    int32 ErrorCode = 0;
};

/**
 * FastNet Client wrapper for Unreal Engine
 * 
 * Provides automatic memory management and TArray support.
 * Thread-safe for use on game thread.
 */
class YOURGAME_API FFastNetClient
{
public:
    FFastNetClient() : Handle(nullptr) {}
    
    ~FFastNetClient()
    {
        Disconnect();
    }
    
    // Non-copyable
    FFastNetClient(const FFastNetClient&) = delete;
    FFastNetClient& operator=(const FFastNetClient&) = delete;
    
    // Movable
    FFastNetClient(FFastNetClient&& Other) noexcept : Handle(Other.Handle)
    {
        Other.Handle = nullptr;
    }
    
    FFastNetClient& operator=(FFastNetClient&& Other) noexcept
    {
        if (this != &Other)
        {
            Disconnect();
            Handle = Other.Handle;
            Other.Handle = nullptr;
        }
        return *this;
    }
    
    /**
     * Connects to a FastNet server
     * @param Host Server address
     * @param Port Server TLS port
     * @return true if connected successfully
     */
    bool Connect(const FString& Host, uint16 Port)
    {
        Disconnect();
        Handle = fastnet_client_connect(TCHAR_TO_UTF8(*Host), Port);
        return Handle != nullptr;
    }
    
    /**
     * Disconnects from the server
     */
    void Disconnect()
    {
        if (Handle)
        {
            fastnet_client_disconnect(Handle);
            Handle = nullptr;
        }
    }
    
    /**
     * Checks if connected
     */
    bool IsConnected() const
    {
        return Handle != nullptr;
    }
    
    /**
     * Sends data to the server
     * @param Channel Channel ID
     * @param Data Data to send
     * @return true if sent successfully
     */
    bool Send(uint8 Channel, const TArray<uint8>& Data)
    {
        if (!Handle || Data.Num() == 0) return false;
        return fastnet_client_send(Handle, Channel, Data.GetData(), Data.Num()) == 0;
    }
    
    /**
     * Sends raw data to the server
     * @param Channel Channel ID
     * @param Data Pointer to data
     * @param Len Data length
     * @return true if sent successfully
     */
    bool SendRaw(uint8 Channel, const uint8* Data, uint32 Len)
    {
        if (!Handle || !Data || Len == 0) return false;
        return fastnet_client_send(Handle, Channel, Data, Len) == 0;
    }
    
    /**
     * Polls for network events
     * @param OutEvent Event structure to fill
     * @return true if an event was received
     */
    bool Poll(FFastNetEvent& OutEvent)
    {
        if (!Handle) return false;
        
        FastNetEvent CEvent;
        if (!fastnet_client_poll(Handle, &CEvent)) return false;
        
        OutEvent.Type = static_cast<EFastNetEventType>(CEvent.type);
        OutEvent.PeerId = CEvent.peer_id;
        OutEvent.Channel = CEvent.channel;
        OutEvent.ErrorCode = CEvent.error_code;
        
        if (CEvent.data && CEvent.data_len > 0)
        {
            OutEvent.Data.SetNumUninitialized(CEvent.data_len);
            FMemory::Memcpy(OutEvent.Data.GetData(), CEvent.data, CEvent.data_len);
        }
        else
        {
            OutEvent.Data.Empty();
        }
        
        return true;
    }
    
    /**
     * Gets the round-trip time in microseconds
     */
    uint64 GetRTT() const
    {
        return Handle ? fastnet_client_rtt_us(Handle) : 0;
    }
    
    /**
     * Gets the round-trip time in milliseconds
     */
    float GetRTTMs() const
    {
        return GetRTT() / 1000.0f;
    }
    
private:
    FastNetClient Handle;
};

/**
 * FastNet Server wrapper for Unreal Engine
 */
class YOURGAME_API FFastNetServer
{
public:
    FFastNetServer() : Handle(nullptr) {}
    
    ~FFastNetServer()
    {
        Destroy();
    }
    
    // Non-copyable
    FFastNetServer(const FFastNetServer&) = delete;
    FFastNetServer& operator=(const FFastNetServer&) = delete;
    
    /**
     * Creates and starts the server
     * @param UdpPort UDP port for game data
     * @param TcpPort TCP port for TLS handshake
     * @param CertPath Path to certificate PEM file
     * @param KeyPath Path to private key PEM file
     * @return true if started successfully
     */
    bool Create(uint16 UdpPort, uint16 TcpPort, const FString& CertPath, const FString& KeyPath)
    {
        Destroy();
        Handle = fastnet_server_create(
            UdpPort, 
            TcpPort, 
            TCHAR_TO_UTF8(*CertPath), 
            TCHAR_TO_UTF8(*KeyPath)
        );
        return Handle != nullptr;
    }
    
    /**
     * Destroys the server
     */
    void Destroy()
    {
        if (Handle)
        {
            fastnet_server_destroy(Handle);
            Handle = nullptr;
        }
    }
    
    /**
     * Checks if server is running
     */
    bool IsRunning() const
    {
        return Handle != nullptr;
    }
    
    /**
     * Sends data to a specific peer
     */
    bool Send(uint16 PeerId, uint8 Channel, const TArray<uint8>& Data)
    {
        if (!Handle || Data.Num() == 0) return false;
        return fastnet_server_send(Handle, PeerId, Channel, Data.GetData(), Data.Num()) == 0;
    }
    
    /**
     * Sends data to all connected peers
     */
    void Broadcast(uint8 Channel, const TArray<uint8>& Data)
    {
        // Note: For production, you'd want to track peer IDs
        // This is a simplified example
    }
    
    /**
     * Polls for network events
     */
    bool Poll(FFastNetEvent& OutEvent)
    {
        if (!Handle) return false;
        
        FastNetEvent CEvent;
        if (!fastnet_server_poll(Handle, &CEvent)) return false;
        
        OutEvent.Type = static_cast<EFastNetEventType>(CEvent.type);
        OutEvent.PeerId = CEvent.peer_id;
        OutEvent.Channel = CEvent.channel;
        OutEvent.ErrorCode = CEvent.error_code;
        
        if (CEvent.data && CEvent.data_len > 0)
        {
            OutEvent.Data.SetNumUninitialized(CEvent.data_len);
            FMemory::Memcpy(OutEvent.Data.GetData(), CEvent.data, CEvent.data_len);
        }
        else
        {
            OutEvent.Data.Empty();
        }
        
        return true;
    }
    
    /**
     * Gets the number of connected peers
     */
    uint32 GetPeerCount() const
    {
        return Handle ? fastnet_server_peer_count(Handle) : 0;
    }
    
private:
    FastNetServer Handle;
};
