use crate::*;
use ferveo_common::TendermintValidator;
use itertools::izip;

pub fn make_validators<E: PairingEngine>(
    validators: Vec<TendermintValidator<E>>,
) -> Vec<ferveo_common::Validator<E>> {
    validators
        .iter()
        .enumerate()
        .map(|(index, validator)| ferveo_common::Validator::<E> {
            validator: validator.clone(),
            share_index: index,
        })
        .collect()
}
