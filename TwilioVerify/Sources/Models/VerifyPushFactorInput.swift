//
//  VerifyPushFactorInput.swift
//  TwilioVerify
//
//  Created by Sergio Fierro on 6/2/20.
//  Copyright © 2020 Twilio. All rights reserved.
//

import Foundation

struct VerifyPushFactorInput: VerifyFactorInput {
  let sid: String
  
  init(withSid sid: String) {
    self.sid = sid
  }
}
