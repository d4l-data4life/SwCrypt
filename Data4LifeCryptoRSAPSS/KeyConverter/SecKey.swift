//
//  File.swift
//  
//
//  Created by Alessio Borraccino on 03.09.21.
//

import Foundation

extension SecKey {
    func asData() throws -> Data {
        var error:Unmanaged<CFError>?
        guard let cfdata = SecKeyCopyExternalRepresentation(self, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        return cfdata as Data
    }

    func asBase64EncodedString() throws -> String {
        return try asData().base64EncodedString()
    }
}
